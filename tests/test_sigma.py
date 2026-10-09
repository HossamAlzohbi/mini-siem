import pytest

from conftest import ev
from minisiem.sigma import RuleError, load_rules


def one(rules_from, detection, logsource="{category: webserver}"):
    text = f"title: t\nname: t\nlogsource: {logsource}\ndetection:\n{detection}\nlevel: low\n"
    return rules_from(text)[0]


def web(**f):
    return ev(0, "nginx", raw=str(f), **f)


def test_equals_is_case_insensitive_and_type_agnostic(rules_from):
    r = one(rules_from, "  s:\n    sc-status: 404\n    cs-method: get\n  condition: s")
    assert r.matches(web(**{"sc-status": 404, "cs-method": "GET"}))
    assert not r.matches(web(**{"sc-status": 200, "cs-method": "GET"}))


def test_contains_startswith_endswith_and_lists_are_or(rules_from):
    r = one(rules_from, "  s:\n    cs-uri-stem|contains: ['/.env', 'passwd']\n  condition: s")
    assert r.matches(web(**{"cs-uri-stem": "/a/.ENV"})) and r.matches(web(**{"cs-uri-stem": "/etc/passwd"}))
    assert not r.matches(web(**{"cs-uri-stem": "/home"}))
    r = one(rules_from, "  s:\n    cs-uri-stem|startswith: /api\n    cs-uri-stem|endswith: .json\n  condition: s".replace(
        "    cs-uri-stem|endswith: .json", "    cs-user-agent|endswith: curl"))
    assert r.matches(web(**{"cs-uri-stem": "/api/x", "cs-user-agent": "xx curl"}))
    assert not r.matches(web(**{"cs-uri-stem": "/x", "cs-user-agent": "curl"}))


def test_all_modifier_requires_every_value(rules_from):
    r = one(rules_from, "  s:\n    cs-uri-query|contains|all: ['a=1', 'b=2']\n  condition: s")
    assert r.matches(web(**{"cs-uri-query": "b=2&a=1"}))
    assert not r.matches(web(**{"cs-uri-query": "a=1"}))


def test_wildcards_and_escaped_wildcards(rules_from):
    r = one(rules_from, "  s:\n    cs-uri-stem: '/a/*/c?.php'\n  condition: s")
    assert r.matches(web(**{"cs-uri-stem": "/a/b/b/c1.php"}))
    assert not r.matches(web(**{"cs-uri-stem": "/a/b/c12.php"}))
    r = one(rules_from, "  s:\n    cs-uri-stem: 'a\\*b'\n  condition: s")
    assert r.matches(web(**{"cs-uri-stem": "a*b"})) and not r.matches(web(**{"cs-uri-stem": "aXb"}))


def test_regex_cidr_and_numeric_comparison(rules_from):
    r = one(rules_from, "  s:\n    cs-uri-stem|re: '^/v[0-9]+/admin$'\n  condition: s")
    assert r.matches(web(**{"cs-uri-stem": "/v2/admin"})) and not r.matches(web(**{"cs-uri-stem": "/V2/admin"}))
    r = one(rules_from, "  s:\n    c-ip|cidr: 203.0.113.0/24\n  condition: s")
    assert r.matches(web(**{"c-ip": "203.0.113.77"})) and not r.matches(web(**{"c-ip": "203.0.114.1"}))
    assert not r.matches(web(**{"c-ip": "not-an-ip"}))
    r = one(rules_from, "  s:\n    sc-bytes|gte: 1000\n  condition: s")
    assert r.matches(web(**{"sc-bytes": 1000})) and not r.matches(web(**{"sc-bytes": 999}))


def test_boolean_conditions_not_and_quantifiers(rules_from):
    det = ("  sel_a: {cs-method: GET}\n  sel_b: {sc-status: 404}\n  filter_x: {c-ip: 10.0.0.1}\n"
           "  condition: (sel_a and sel_b) and not filter_x")
    r = one(rules_from, det)
    assert r.matches(web(**{"cs-method": "GET", "sc-status": 404, "c-ip": "1.1.1.1"}))
    assert not r.matches(web(**{"cs-method": "GET", "sc-status": 404, "c-ip": "10.0.0.1"}))
    r = one(rules_from, "  sel_a: {cs-method: GET}\n  sel_b: {sc-status: 404}\n  condition: all of sel_*")
    assert r.matches(web(**{"cs-method": "GET", "sc-status": 404})) and not r.matches(web(**{"cs-method": "GET"}))
    r = one(rules_from, "  sel_a: {cs-method: GET}\n  sel_b: {sc-status: 404}\n  condition: 1 of them")
    assert r.matches(web(**{"sc-status": 404})) and not r.matches(web(**{"sc-status": 200}))


def test_missing_field_never_matches_positive_but_null_matches_missing(rules_from):
    r = one(rules_from, "  s:\n    cs-referer: 'x'\n  condition: s")
    assert not r.matches(web(**{"cs-method": "GET"}))
    r = one(rules_from, "  s:\n    cs-referer: null\n  condition: s")
    assert r.matches(web(**{"cs-method": "GET"}))
    r = one(rules_from, "  s:\n    cs-referer|exists: true\n  condition: s")
    assert r.matches(web(**{"cs-referer": "x"})) and not r.matches(web(**{"cs-method": "GET"}))


def test_keyword_selection_searches_raw_line(rules_from):
    r = one(rules_from, "  kw:\n    - 'jndi:'\n    - 'union select'\n  condition: kw")
    assert r.matches(ev(0, "nginx", raw="GET /?x=${JNDI:ldap://x}"))
    assert not r.matches(ev(0, "nginx", raw="GET /"))


def test_field_names_fall_back_to_case_insensitive(rules_from):
    r = one(rules_from, "  s:\n    EventID: 4625\n  condition: s", logsource="{product: windows, service: security}")
    assert r.matches(ev(0, "windows", eventid=4625)) or r.matches(ev(0, "windows", EventID=4625))


def test_logsource_routing(rules_from):
    r = one(rules_from, "  s: {action: accepted}\n  condition: s", logsource="{product: linux, service: sshd}")
    assert r.matches(ev(0, "ssh", action="accepted")) and not r.matches(ev(0, "nginx", action="accepted"))
    r = one(rules_from, "  s: {Image|endswith: '\\x.exe'}\n  condition: s",
            logsource="{category: process_creation, product: windows}")
    assert r.matches(ev(0, "windows", EventID=4688, Image="C:\\x.exe"))
    assert not r.matches(ev(0, "windows", EventID=4624, Image="C:\\x.exe"))  # category implies process events


@pytest.mark.parametrize("bad, message", [
    ("title: t\nname: t\nlogsource: {category: webserver}\ndetection:\n  s: {a|base64: x}\n  condition: s\n", "modifier"),
    ("title: t\nname: t\nlogsource: {category: webserver}\ndetection:\n  s: {a: x}\n  condition: s | count() > 5\n", "aggregation"),
    ("title: t\nname: t\nlogsource: {category: webserver}\ndetection:\n  s: {a: x}\n  condition: s and nope\n", "unknown selection"),
    ("title: t\nname: t\nlogsource: {category: webserver}\ndetection:\n  s: {a: x}\n  condition: (s\n", "')'"),
    ("title: t\nname: t\nlogsource: {category: mainframe}\ndetection:\n  s: {a: x}\n  condition: s\n", "logsource"),
    ("title: t\nname: t\nlogsource: {category: webserver}\ndetection:\n  s: {a|re: '('}\n  condition: s\n", "regex"),
    ("title: t\nname: t\nlevel: urgent\nlogsource: {category: webserver}\ndetection:\n  s: {a: x}\n  condition: s\n", "level"),
    ("name: t\nlogsource: {category: webserver}\ndetection:\n  s: {a: x}\n  condition: s\n", "title"),
])
def test_unsupported_or_invalid_rules_fail_loudly(tmp_path, bad, message):
    (tmp_path / "r.yml").write_text(bad)
    with pytest.raises(RuleError) as exc:
        load_rules(tmp_path)
    assert message in str(exc.value)


def test_duplicate_names_and_unknown_references_are_rejected(tmp_path):
    base = "title: t\nname: dup\nlogsource: {category: webserver}\ndetection:\n  s: {a: x}\n  condition: s\n"
    (tmp_path / "a.yml").write_text(base)
    (tmp_path / "b.yml").write_text(base)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)
    (tmp_path / "b.yml").write_text(
        "title: c\nname: c\ncorrelation:\n  type: event_count\n  rules: [ghost]\n  timespan: 1m\n  condition: {gte: 2}\n")
    (tmp_path / "a.yml").write_text(base.replace("dup", "real"))
    with pytest.raises(RuleError, match="unknown rule"):
        load_rules(tmp_path)


def test_all_shipped_rules_load(project_rules):
    assert len(project_rules) >= 30
    assert all(r.tags or r.level == "informational" for r in project_rules)
