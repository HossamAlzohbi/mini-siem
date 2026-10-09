"""Documented blind spots.

Each test below passes *because the detection misses the attack*. They exist so the limits are
written down and verified rather than hidden. If you close a gap, flip the assertion and move
the entry out of the README's "Known gaps" section.
"""
import itertools

from minisiem.engine import Engine
from minisiem.parsers import nginx, ssh, windows
from minisiem.sigma import load_rules

RULES = load_rules("rules")
_ids = itertools.count(1)


def alerts_for(events):
    for e in events:
        e.id = next(_ids)
    return Engine(RULES).run(events)


def web(ts, ip, uri, ua="Mozilla/5.0", status=200):
    from datetime import datetime, timezone
    t = datetime.fromtimestamp(1_790_000_000 + ts, timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return nginx.parse_line(f'{ip} - - [{t}] "GET {uri} HTTP/1.1" {status} 10 "-" "{ua}"')


def sshfail(ts, ip, user="root"):
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(1_790_000_000 + ts, timezone.utc)
    t = f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S}"  # '%e' is not available on Windows
    return ssh.parse_line(f"{t} h sshd[1]: Failed password for {user} from {ip} port 22 ssh2", year=2026)


def test_control_plain_sqli_is_detected():
    assert {a.rule for a in alerts_for([web(0, "1.1.1.1", "/p?id=1%20union%20select%201")])} == {"web_sqli"}


def test_gap_double_encoded_sql_injection():
    assert alerts_for([web(0, "1.1.1.1", "/p?id=1%2520union%2520select%25201")]) == []


def test_gap_comment_obfuscated_sql_injection():
    assert alerts_for([web(0, "1.1.1.1", "/p?id=1/**/UNION/**/SELECT/**/1")]) == []


def test_gap_distributed_brute_force_across_many_addresses():
    events = [sshfail(i * 5, f"203.0.113.{i + 1}") for i in range(40)]
    assert alerts_for(events) == []


def test_gap_very_slow_brute_force_stays_under_the_hourly_threshold():
    events = [sshfail(i * 240, "203.0.113.9") for i in range(45)]  # 15 per hour for 3 hours
    assert alerts_for(events) == []


def test_gap_renamed_credential_dumping_tool_with_unlisted_arguments():
    ev = windows.parse_json_line(
        '{"@timestamp":"2026-10-05T10:00:00Z","winlog":{"event_id":"4688","computer_name":"WS1","channel":"Security",'
        '"event_data":{"NewProcessName":"C:\\\\Temp\\\\a.exe","CommandLine":"a.exe \\"lsadump::sam\\"",'
        '"ParentProcessName":"C:\\\\Windows\\\\explorer.exe"}}}')
    assert alerts_for([ev]) == []
