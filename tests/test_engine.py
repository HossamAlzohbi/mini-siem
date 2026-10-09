from conftest import ev, ssh_fail, ssh_ok
from minisiem.engine import Engine

BASE = """
title: failed
name: failed
logsource: {product: linux, service: sshd}
detection:
  s: {action: failed_password}
  condition: s
level: informational
---
title: accepted
name: accepted
logsource: {product: linux, service: sshd}
detection:
  s: {action: accepted}
  condition: s
level: informational
---
"""


def run(rules_from, corr, events):
    rules = rules_from(BASE + corr)
    return Engine(rules).run(events)


COUNT = """title: brute
name: brute
correlation:
  type: event_count
  rules: [failed]
  group-by: [src_ip]
  timespan: 60s
  condition: {gte: 5}
level: high
"""


def test_threshold_boundary(rules_from):
    assert run(rules_from, COUNT, [ssh_fail(i) for i in range(4)]) == []
    alerts = run(rules_from, COUNT, [ssh_fail(i) for i in range(5)])
    assert [a.rule for a in alerts] == ["brute"] and alerts[0].count == 5


def test_events_outside_window_do_not_add_up(rules_from):
    events = [ssh_fail(i * 20) for i in range(5)]  # 5 events over 80 s: never 5 within 60 s
    assert run(rules_from, COUNT, events) == []


def test_continuous_attack_is_one_alert_then_a_gap_makes_a_second(rules_from):
    first = [ssh_fail(i) for i in range(30)]
    second = [ssh_fail(1000 + i) for i in range(6)]
    alerts = run(rules_from, COUNT, first + second)
    assert len(alerts) == 2
    assert alerts[0].count == 30 and alerts[1].count == 6
    assert alerts[0].ts_trigger < alerts[0].ts_last


def test_groups_are_independent(rules_from):
    events = [ssh_fail(i, ip=f"203.0.113.{i}") for i in range(10)]  # 10 sources, 1 failure each
    assert run(rules_from, COUNT, events) == []
    events = [ssh_fail(i, ip="1.1.1.1") for i in range(5)] + [ssh_fail(i, ip="2.2.2.2") for i in range(3)]
    alerts = run(rules_from, COUNT, events)
    assert [a.group for a in alerts] == [{"src_ip": "1.1.1.1"}]


def test_building_block_rules_are_silent_but_alert_true_overrides(rules_from):
    events = [ssh_fail(i) for i in range(5)]
    assert {a.rule for a in run(rules_from, COUNT, events)} == {"brute"}
    forced = BASE.replace("level: informational\n---\ntitle: accepted", "alert: true\nlevel: informational\n---\ntitle: accepted", 1)
    rules = rules_from(forced + COUNT)
    assert {a.rule for a in Engine(rules).run(events)} == {"failed", "brute"}


def test_single_event_alerts_merge_into_bursts_per_entity(rules_from):
    rules = rules_from("title: root\nname: root\nlogsource: {product: linux, service: sshd}\n"
                       "detection:\n  s: {action: accepted, user: root}\n  condition: s\nlevel: medium\n")
    events = [ssh_ok(0), ssh_ok(30), ssh_ok(60), ssh_ok(5000), ssh_ok(10, ip="9.9.9.9")]
    alerts = Engine(rules).run(events)
    by_entity = sorted((a.group["entity"], a.count) for a in alerts)
    assert by_entity == [("203.0.113.5", 1), ("203.0.113.5", 3), ("9.9.9.9", 1)]


DISTINCT = """title: spray
name: spray
correlation:
  type: value_count
  rules: [failed]
  group-by: [src_ip]
  timespan: 10m
  condition: {gte: 3, field: user}
level: high
"""


def test_value_count_counts_distinct_values(rules_from):
    assert run(rules_from, DISTINCT, [ssh_fail(i, user="root") for i in range(20)]) == []
    alerts = run(rules_from, DISTINCT, [ssh_fail(i, user=u) for i, u in enumerate(["a", "b", "c"])])
    assert len(alerts) == 1


TEMPORAL = """title: both
name: both
correlation:
  type: temporal
  rules: [failed, accepted]
  group-by: [src_ip]
  timespan: 60s
  condition: {}
level: high
"""
ORDERED = TEMPORAL.replace("temporal\n", "temporal_ordered\n").replace("name: both", "name: seq")


def test_temporal_ignores_order_ordered_does_not(rules_from):
    reverse = [ssh_ok(0), ssh_fail(10)]
    forward = [ssh_fail(0), ssh_ok(10)]
    assert len(run(rules_from, TEMPORAL, reverse)) == 1
    assert run(rules_from, ORDERED, reverse) == []
    assert len(run(rules_from, ORDERED, forward)) == 1
    assert run(rules_from, ORDERED, [ssh_fail(0), ssh_ok(120)]) == []  # outside the timespan


def test_correlation_can_reference_a_correlation(rules_from):
    chained = COUNT + "---\n" + """title: owned
name: owned
correlation:
  type: temporal_ordered
  rules: [brute, accepted]
  group-by: [src_ip]
  timespan: 5m
level: critical
"""
    events = [ssh_fail(i) for i in range(6)] + [ssh_ok(30)]
    alerts = run(rules_from, chained, events)
    assert {a.rule for a in alerts} == {"owned"}  # brute is silenced because 'owned' references it
    # a successful login from the same address with only two failures is not a compromise
    assert run(rules_from, chained, [ssh_fail(0), ssh_fail(1), ssh_ok(5)]) == []
    # a successful login from a different address does not match either
    assert run(rules_from, chained, [ssh_fail(i) for i in range(6)] + [ssh_ok(30, ip="8.8.8.8")]) == []


def test_aliases_join_different_field_names(rules_from):
    web = """title: w
name: w
logsource: {category: webserver}
detection:
  s: {sc-status: 401}
  condition: s
level: informational
---
title: cross
name: cross
correlation:
  type: temporal
  rules: [failed, w]
  group-by: [ip]
  aliases:
    ip: {failed: src_ip, w: c-ip}
  timespan: 5m
level: high
"""
    events = [ssh_fail(0, ip="7.7.7.7"), ev(20, "nginx", **{"c-ip": "7.7.7.7", "sc-status": 401})]
    assert [a.rule for a in run(rules_from, web, events)] == ["cross"]
    events = [ssh_fail(0, ip="7.7.7.7"), ev(20, "nginx", **{"c-ip": "6.6.6.6", "sc-status": 401})]
    assert run(rules_from, web, events) == []


def test_missing_group_value_is_skipped(rules_from):
    events = [ev(i, "ssh", action="failed_password", user="x") for i in range(10)]  # no src_ip
    assert run(rules_from, COUNT, events) == []


def test_correlation_cycle_is_rejected(rules_from):
    import pytest
    from minisiem.sigma import RuleError
    cyc = """title: a
name: a
correlation: {type: event_count, rules: [b], timespan: 1m, condition: {gte: 1}}
---
title: b
name: b
correlation: {type: event_count, rules: [a], timespan: 1m, condition: {gte: 1}}
"""
    with pytest.raises(RuleError, match="cycle"):
        Engine(rules_from(cyc))


def test_engine_is_deterministic_and_order_independent(rules_from):
    events = [ssh_fail(i) for i in range(12)] + [ssh_ok(15)]
    a = run(rules_from, COUNT, events)
    b = run(rules_from, COUNT, list(reversed(events)))
    assert [(x.rule, x.count, x.ts_first) for x in a] == [(x.rule, x.count, x.ts_first) for x in b]
