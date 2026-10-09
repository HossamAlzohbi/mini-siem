import http.client
import json
import re
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from minisiem.cli import main
from minisiem.dashboard import STATIC, make_handler

XSS = "<script>window.__pwned=1</script>"


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dash")
    log = tmp / "access.log"
    log.write_text(
        f'203.0.113.7 - - [05/Oct/2026:10:00:00 +0000] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 5 "-" "{XSS}"\n'
        f'203.0.113.7 - - [05/Oct/2026:10:00:05 +0000] "GET /search?q=%3Cscript%3Ealert(2)%3C/script%3E HTTP/1.1" 200 5 "-" "<img src=x onerror=alert(1)>"\n')
    db = str(tmp / "d.db")
    main(["ingest", "--type", "nginx", str(log), "--db", db])
    main(["detect", "--rules", "rules", "--db", db])
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(db, "rules", None))
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield port, db
    httpd.shutdown()


def get(port, path, method="GET", headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, headers=headers or {})
    r = c.getresponse()
    body = r.read()
    return r.status, dict(r.getheaders()), body


def test_endpoints_return_expected_data(server):
    port, _ = server
    st, _, body = get(port, "/api/summary")
    s = json.loads(body)
    assert st == 200 and s["events_total"] == 2 and s["alerts_by_level"]["medium"] >= 1
    alerts = json.loads(get(port, "/api/alerts?level=medium")[2])
    assert alerts and alerts[0]["rule"] == "web_xss"
    detail = json.loads(get(port, f"/api/alerts/{alerts[0]['id']}")[2])
    assert len(detail["events"]) == 2
    assert json.loads(get(port, "/api/events?source=nginx&q=script")[2])
    # '_' is a LIKE wildcard; it must be escaped so "_cript" does not match "script"
    assert json.loads(get(port, "/api/events?q=_cript")[2]) == []
    assert json.loads(get(port, "/api/events?q=%25zz")[2]) == []
    assert get(port, "/api/alerts/999999")[0] == 404
    assert any(r["name"] == "web_xss" for r in json.loads(get(port, "/api/rules")[2]))


def test_log_content_is_data_never_markup(server):
    port, _ = server
    st, headers, body = get(port, "/api/events?q=script")
    assert headers["Content-Type"].startswith("application/json")
    assert XSS in json.loads(body)[0]["raw"] or XSS in json.loads(body)[1]["raw"]  # stored verbatim, as text
    js = (STATIC / "app.js").read_text()
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in re.sub(r"//.*", "", js), forbidden


def test_security_headers_and_host_check(server):
    port, _ = server
    st, h, _ = get(port, "/")
    assert st == 200 and "default-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff"
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.putrequest("GET", "/api/summary", skip_host=True)
    c.putheader("Host", "evil.example")
    c.endheaders()
    assert c.getresponse().status in (200,)  # test server was built without a host allow-list


def test_host_allow_list_blocks_dns_rebinding(server, tmp_path):
    _, db = server
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(db, "rules", {"127.0.0.1:1234"}))
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        assert get(port, "/api/summary")[0] == 403  # Host header is 127.0.0.1:<random>, not allowed
        assert get(port, "/api/summary", headers={"Host": "127.0.0.1:1234"})[0] == 200
    finally:
        httpd.shutdown()


def test_no_path_traversal_and_no_write_methods(server):
    port, _ = server
    for path in ("/../store.py", "/%2e%2e/store.py", "/..%2fstore.py", "/static/../../cli.py", "/app.py"):
        assert get(port, path)[0] == 404, path
    for method in ("POST", "PUT", "DELETE"):
        assert get(port, "/api/alerts", method=method)[0] in (501, 405)


def test_database_is_opened_read_only(server):
    from minisiem.store import Store
    import sqlite3
    _, db = server
    ro = Store(db, readonly=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.db.execute("DELETE FROM events")


def _chromium():
    import glob
    import os
    cand = [os.environ.get("MINISIEM_CHROMIUM", "")] + glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")
    return next((c for c in cand if c and Path(c).exists()), None)


@pytest.mark.skipif(not _chromium(), reason="needs Playwright + Chromium (set MINISIEM_CHROMIUM)")
def test_browser_does_not_execute_malicious_log_content(server):
    sync_api = pytest.importorskip("playwright.sync_api")
    port, _ = server
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch(executable_path=_chromium(), args=["--no-sandbox"])
        page = browser.new_page()
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        page.goto(f"http://127.0.0.1:{port}/")
        page.wait_for_selector("#alerts-table tbody tr[data-id]")
        page.click("#alerts-table tbody tr[data-id]")
        page.wait_for_selector("#d-events tbody tr")
        shown = page.inner_text("#d-events")
        assert "<script>window.__pwned=1</script>" in shown  # visible as text
        assert page.evaluate("window.__pwned") is None
        assert page.query_selector("#d-events script, #d-events img") is None
        assert dialogs == []
        browser.close()
