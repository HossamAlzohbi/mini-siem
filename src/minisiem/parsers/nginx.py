"""nginx/Apache "combined" access log parser.

Format: ``$remote_addr - $remote_user [$time_local] "$request" $status
$body_bytes_sent "$http_referer" "$http_user_agent"``.

Field names follow the Sigma ``webserver`` taxonomy. ``cs-uri-query`` is
URL-decoded once so rules can match ``union select`` instead of ``union%20select``.
Double-encoded payloads are therefore *not* decoded (a documented limitation).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterator
from urllib.parse import unquote_plus

from ..models import Event

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)")?'
)


def parse_line(line: str, host: str = "web") -> Event | None:
    line = line.rstrip("\r\n")
    m = LINE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None

    request = m["request"]
    parts = request.split(" ")
    if len(parts) >= 2:
        method, uri = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else ""
    else:  # malformed request such as a TLS handshake sent to the HTTP port
        method, uri, version = "", request, ""

    stem, _, query = uri.partition("?")
    fields = {
        "c-ip": m["ip"],
        "cs-username": "" if m["user"] == "-" else m["user"],
        "cs-method": method,
        "cs-uri": uri,
        "cs-uri-stem": unquote_plus(stem),
        "cs-uri-query": unquote_plus(query),
        "cs-version": version,
        "sc-status": int(m["status"]),
        "sc-bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
        "cs-referer": m["referer"] or "",
        "cs-user-agent": m["agent"] or "",
    }
    return Event(ts=ts, source="nginx", host=host, fields=fields, raw=line)


def parse_lines(lines, host: str = "web") -> Iterator[Event | None]:
    for line in lines:
        if line.strip():
            yield parse_line(line, host)


def parse_file(path: str, host: str = "web", **_) -> Iterator[tuple[int, str, Event | None]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                yield n, line.rstrip("\r\n"), parse_line(line, host)
