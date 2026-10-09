"""Read-only web dashboard using only the standard library.

Security notes
--------------
* Binds to 127.0.0.1 by default and validates the ``Host`` header (blocks DNS rebinding).
* The database is opened read-only; the server accepts GET only.
* Log content is attacker-controlled. The API returns it as JSON and the front end renders it
  with ``textContent`` only (never ``innerHTML``), and a strict Content-Security-Policy is set.
* There is **no authentication**. Do not expose it beyond localhost without a reverse proxy that adds it.
"""
from __future__ import annotations

import json
import re
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .engine import MISSING
from .models import LEVELS, iso
from .sigma import RuleError, load_rules
from .store import Store

STATIC = Path(__file__).parent / "static"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_LIMIT = 500


def _alert_json(a) -> dict:
    return {"id": a.id, "rule": a.rule, "title": a.title, "level": a.level, "description": a.description,
            "tags": a.tags, "kind": a.kind, "first": iso(a.ts_first), "last": iso(a.ts_last),
            "trigger": iso(a.ts_trigger), "count": a.count, "group": a.group}


def _event_json(e) -> dict:
    return {"id": e.id, "time": iso(e.ts), "source": e.source, "host": e.host, "raw": e.raw}


def build_summary(store: Store) -> dict:
    events_by_source = {r["source"]: r["n"] for r in
                        store.db.execute("SELECT source, COUNT(*) AS n FROM events GROUP BY source")}
    span = store.db.execute("SELECT MIN(ts) AS a, MAX(ts) AS b FROM events").fetchone()
    alerts = list(store.iter_alerts())
    by_level = {lvl: 0 for lvl in LEVELS}
    by_rule: dict[str, int] = {}
    entities: dict[str, dict] = {}
    for a in alerts:
        by_level[a.level] += 1
        by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
        for v in a.group.values():
            if v in MISSING:
                continue
            e = entities.setdefault(str(v), {"entity": str(v), "alerts": 0, "worst": 0})
            e["alerts"] += 1
            e["worst"] = max(e["worst"], LEVELS.index(a.level))
    timeline: list[dict] = []
    if alerts:
        lo, hi = min(a.ts_first for a in alerts), max(a.ts_first for a in alerts)
        size = 3600 if hi - lo <= 3 * 86400 else 86400
        start = int(lo // size * size)
        buckets = {}
        for a in alerts:
            b = int(a.ts_first // size * size)
            buckets.setdefault(b, {lvl: 0 for lvl in LEVELS})[a.level] += 1
        n = min(int((hi - start) // size) + 1, 400)
        timeline = [{"t": iso(start + i * size), "levels": buckets.get(start + i * size, {lvl: 0 for lvl in LEVELS})}
                    for i in range(n)]
        bucket_seconds = size
    else:
        bucket_seconds = 3600
    top = sorted(entities.values(), key=lambda e: (-e["worst"], -e["alerts"]))[:8]
    for e in top:
        e["worst"] = LEVELS[e["worst"]]
    return {
        "events_total": sum(events_by_source.values()), "events_by_source": events_by_source,
        "range": [iso(span["a"]), iso(span["b"])] if span["a"] is not None else None,
        "alerts_total": len(alerts), "alerts_by_level": by_level,
        "alerts_by_rule": sorted(({"rule": k, "count": v} for k, v in by_rule.items()),
                                 key=lambda r: -r["count"]),
        "timeline": timeline, "bucket_seconds": bucket_seconds, "top_entities": top,
    }


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def make_handler(db_path: str, rules_dir: str | None, allowed_hosts: set[str] | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MiniSIEM"

        def log_message(self, fmt, *args):  # quiet by default
            if "-v" in sys.argv:
                super().log_message(fmt, *args)

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status: int = 200) -> None:
            self._send(status, json.dumps(obj).encode(), "application/json")

        def _error(self, status: int, msg: str) -> None:
            self._json({"error": msg}, status)

        def do_GET(self) -> None:  # noqa: N802
            if allowed_hosts is not None and self.headers.get("Host", "") not in allowed_hosts:
                return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
            url = urlparse(self.path)
            q = {k: v[-1] for k, v in parse_qs(url.query).items()}
            path = url.path
            try:
                if path.startswith("/api/"):
                    return self._api(path, q)
                return self._static(path)
            except FileNotFoundError:
                return self._error(HTTPStatus.NOT_FOUND, "database not found")
            except Exception as exc:  # never leak a traceback to the browser
                print(f"error handling {self.path}: {exc!r}", file=sys.stderr)
                return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal error")

        def _static(self, path: str) -> None:
            name = "index.html" if path in ("/", "") else path.lstrip("/")
            target = (STATIC / name).resolve()
            if STATIC.resolve() not in target.parents or not target.is_file() or target.suffix not in TYPES:
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            self._send(200, target.read_bytes(), TYPES[target.suffix])

        def _api(self, path: str, q: dict) -> None:
            store = Store(db_path, readonly=True)
            try:
                if path == "/api/summary":
                    return self._json(build_summary(store))
                if path == "/api/alerts":
                    floor = LEVELS.index(q["level"]) if q.get("level") in LEVELS else 0
                    term = q.get("q", "").lower()
                    rows = [a for a in store.iter_alerts() if LEVELS.index(a.level) >= floor and
                            (not term or term in a.rule.lower() or term in a.title.lower() or
                             term in json.dumps(a.group).lower())]
                    rows.sort(key=lambda a: (-LEVELS.index(a.level), a.ts_first))
                    return self._json([_alert_json(a) for a in rows[:MAX_LIMIT]])
                m = re.fullmatch(r"/api/alerts/(\d+)", path)
                if m:
                    a = store.get_alert(int(m[1]))
                    if a is None:
                        return self._error(HTTPStatus.NOT_FOUND, "no such alert")
                    events = store.events_by_id(a.event_ids[:200])
                    return self._json({**_alert_json(a), "events": [_event_json(e) for e in events],
                                       "events_shown": len(events)})
                if path == "/api/events":
                    limit = max(1, min(int(q.get("limit", 100)), MAX_LIMIT))
                    sql, args = "SELECT * FROM events WHERE 1=1", []
                    if q.get("source") in ("nginx", "ssh", "windows"):
                        sql += " AND source = ?"
                        args.append(q["source"])
                    if q.get("q"):
                        sql += " AND raw LIKE ? ESCAPE '\\'"
                        args.append(_like(q["q"][:200]))
                    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
                    args.append(limit)
                    return self._json([_event_json(store._event(r)) for r in store.db.execute(sql, args)])
                if path == "/api/rules":
                    counts = {r["rule"]: r["n"] for r in
                              store.db.execute("SELECT rule, COUNT(*) AS n FROM alerts GROUP BY rule")}
                    try:
                        rules = load_rules(rules_dir) if rules_dir else []
                    except RuleError:
                        rules = []
                    return self._json([{"name": r.name, "title": r.title, "level": r.level,
                                        "description": r.description, "tags": r.tags,
                                        "type": r.corr["type"] if r.corr else "rule",
                                        "alerts": counts.get(r.name, 0)} for r in rules])
                return self._error(HTTPStatus.NOT_FOUND, "unknown endpoint")
            finally:
                store.close()

    return Handler


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8765, rules_dir: str | None = None) -> int:
    from .cli import default_rules_dir
    if not Path(db_path).is_file():
        print(f"error: database {db_path} not found (run `minisiem ingest` / `minisiem demo` first)",
              file=sys.stderr)
        return 2
    loopback = host in ("127.0.0.1", "localhost", "::1")
    allowed = {f"{h}:{port}" for h in ("127.0.0.1", "localhost", "[::1]")} if loopback else None
    if not loopback:
        print("WARNING: binding to a non-loopback address. The dashboard has no authentication.",
              file=sys.stderr)
    httpd = ThreadingHTTPServer((host, port), make_handler(db_path, rules_dir or default_rules_dir(), allowed))
    print(f"MiniSIEM dashboard on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
