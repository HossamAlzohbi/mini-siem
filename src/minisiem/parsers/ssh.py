"""OpenSSH (sshd) log parser for syslog files such as ``/var/log/auth.log``.

Supports both the traditional syslog timestamp (``Oct  5 10:00:01``, no year,
so a year must be supplied) and the ISO-8601 timestamp used by newer rsyslog /
journald exports.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Iterator

from ..models import Event

HEADER = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)|"
    r"(?P<sys>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

IP = r"(?P<ip>[0-9a-fA-F:.]+)"
PATTERNS = [
    ("failed_password", re.compile(
        rf"Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
        rf"(?P<invalid>invalid user )?(?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("accepted", re.compile(
        rf"Accepted (?P<method>password|publickey|keyboard-interactive/pam|hostbased|gssapi\S*) for "
        rf"(?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("invalid_user", re.compile(rf"Invalid user (?P<user>\S*) from {IP}(?: port (?P<port>\d+))?")),
    ("preauth_close", re.compile(
        rf"(?:Connection closed by|Disconnected from) (?:authenticating |invalid )?(?:user (?P<user>\S+) )?"
        rf"{IP}(?: port (?P<port>\d+))?.*\[preauth\]")),
    ("max_auth", re.compile(
        rf"(?:maximum authentication attempts exceeded for|error: maximum authentication attempts exceeded for) "
        rf"(?:invalid user )?(?P<user>\S+) from {IP} port (?P<port>\d+)")),
]


def _parse_ts(m: re.Match, year: int, tz: timezone) -> float | None:
    if m["iso"]:
        text = m["iso"].replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        return dt.timestamp()
    try:
        dt = datetime.strptime(f"{year} {' '.join(m['sys'].split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=tz).timestamp()


def parse_line(line: str, year: int | None = None, tz: timezone = timezone.utc,
               now: float | None = None) -> Event | None:
    line = line.rstrip("\r\n")
    m = HEADER.match(line)
    if not m:
        return None
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    year = year or datetime.fromtimestamp(now, tz).year
    ts = _parse_ts(m, year, tz)
    if ts is None:
        return None
    # Year-less timestamps: a December line read in January belongs to last year.
    if m["sys"] and ts > now + 86400:
        ts = _parse_ts(m, year - 1, tz) or ts

    msg = m["msg"]
    fields = {"message": msg, "process_id": m["pid"] or "", "service": "sshd"}
    for action, pattern in PATTERNS:
        pm = pattern.search(msg)
        if pm:
            d = pm.groupdict()
            fields.update(
                action=action,
                user=d.get("user") or "",
                src_ip=d.get("ip") or "",
                src_port=int(d["port"]) if d.get("port") else 0,
                auth_method=(d.get("method") or ""),
                invalid_user=bool(d.get("invalid")) or action == "invalid_user",
            )
            break
    else:
        fields["action"] = "other"
    return Event(ts=ts, source="ssh", host=m["host"], fields=fields, raw=line)


def parse_file(path: str, host: str = "", year: int | None = None, tz: timezone = timezone.utc,
               **_) -> Iterator[tuple[int, str, Event | None]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            ev = parse_line(line, year=year, tz=tz)
            if ev and host:
                ev.host = host
            yield n, line.rstrip("\r\n"), ev
