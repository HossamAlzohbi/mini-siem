from datetime import timezone

from minisiem.parsers import nginx, ssh, windows

DATA = __import__("pathlib").Path(__file__).parent / "data"


def test_nginx_combined_line():
    e = nginx.parse_line('203.0.113.9 - bob [05/Oct/2026:10:00:01 +0200] "GET /a/b?q=union%20select%201 HTTP/1.1" '
                         '404 12 "https://x.test/" "sqlmap/1.7"')
    assert e.ts == 1791187201.0 - 0  # 08:00:01 UTC
    f = e.fields
    assert (f["c-ip"], f["cs-username"], f["cs-method"], f["cs-uri-stem"]) == ("203.0.113.9", "bob", "GET", "/a/b")
    assert f["cs-uri-query"] == "q=union select 1"  # decoded once
    assert f["sc-status"] == 404 and f["cs-user-agent"] == "sqlmap/1.7"


def test_nginx_tolerates_dash_bytes_missing_referer_and_garbage_request():
    e = nginx.parse_line('1.2.3.4 - - [05/Oct/2026:10:00:01 +0000] "\\x16\\x03\\x01" 400 - "-" "-"')
    assert e is not None and e.fields["cs-method"] == "" and e.fields["sc-bytes"] == 0
    e = nginx.parse_line('1.2.3.4 - - [05/Oct/2026:10:00:01 +0000] "GET / HTTP/1.0" 200 5')
    assert e is not None and e.fields["cs-user-agent"] == ""
    assert nginx.parse_line("not a log line") is None


def test_ssh_syslog_failed_invalid_accepted():
    e = ssh.parse_line("Oct  5 10:00:01 web01 sshd[12]: Failed password for invalid user admin from 198.51.100.7 "
                       "port 4444 ssh2", year=2026)
    assert e.fields["action"] == "failed_password" and e.fields["invalid_user"] is True
    assert (e.fields["user"], e.fields["src_ip"], e.fields["src_port"]) == ("admin", "198.51.100.7", 4444)
    e = ssh.parse_line("Oct 15 10:00:01 web01 sshd[12]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2: RSA SHA256:x",
                       year=2026)
    assert e.fields["action"] == "accepted" and e.fields["auth_method"] == "publickey"
    e = ssh.parse_line("Oct  5 10:00:01 web01 sshd[12]: Invalid user oracle from 198.51.100.7 port 1", year=2026)
    assert e.fields["action"] == "invalid_user"
    e = ssh.parse_line("Oct  5 10:00:01 web01 sshd[12]: Server listening on 0.0.0.0 port 22.", year=2026)
    assert e.fields["action"] == "other"
    assert ssh.parse_line("Oct  5 10:00:01 web01 cron[1]: hello") is None


def test_ssh_iso_timestamp_with_offset():
    e = ssh.parse_line("2026-10-05T10:00:01.123456+02:00 web01 sshd[1]: Accepted password for a from 1.1.1.1 port 2 ssh2")
    assert e.ts == 1791187201.123456


def test_ssh_year_rollover():
    # a December line read on 2 January belongs to the previous year
    import datetime as dt
    now = dt.datetime(2027, 1, 2, tzinfo=timezone.utc).timestamp()
    e = ssh.parse_line("Dec 31 23:59:59 h sshd[1]: Failed password for a from 1.1.1.1 port 2 ssh2", year=2027, now=now)
    assert dt.datetime.fromtimestamp(e.ts, timezone.utc).year == 2026


def test_windows_winlogbeat_json():
    line = ('{"@timestamp":"2026-10-05T10:00:00.000Z","winlog":{"event_id":"4688","computer_name":"WS1",'
            '"channel":"Security","event_data":{"NewProcessName":"C:\\\\x\\\\a.exe","CommandLine":"a.exe -x",'
            '"ParentProcessName":"C:\\\\x\\\\p.exe"}}}')
    e = windows.parse_json_line(line)
    assert e.fields["EventID"] == 4688 and e.host == "WS1"
    assert e.fields["Image"].endswith("a.exe") and e.fields["ParentImage"].endswith("p.exe")


def test_windows_flat_json_and_bad_input():
    e = windows.parse_json_line('{"TimeCreated":"2026-10-05T10:00:00Z","EventID":4720,"Computer":"DC1",'
                                '"EventData":{"TargetUserName":"x"}}')
    assert e.fields["EventID"] == 4720 and e.fields["TargetUserName"] == "x"
    assert windows.parse_json_line("{not json") is None
    assert windows.parse_json_line('{"EventID": "abc", "TimeCreated": "2026-10-05T10:00:00Z"}') is None
    assert windows.parse_json_line('{"EventID": 1}') is None  # no timestamp


def test_windows_xml_export_with_namespace_and_nanoseconds():
    rows = list(windows.parse_file(str(DATA / "events_sample.xml")))
    assert len(rows) == 2 and all(r[2] for r in rows)
    first = rows[0][2]
    assert first.fields["EventID"] == 4625 and first.fields["IpAddress"] == "203.0.113.50"
    assert first.fields["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert first.host.startswith("SRV-FILE01")
    assert rows[1][2].fields["Image"].endswith("cmd.exe")
