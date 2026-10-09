"""Score detections against the ground truth written by ``simulate``.

Definitions (kept deliberately simple and stated in the report):

* An *expectation* is a (scenario, rule) pair: "this attack should trigger that rule".
* It is *detected* when an alert from that rule involves one of the scenario's attacker
  addresses (or, for scenarios without an address, the same host within the scenario's time window).
* *Time to detect* is the time between the scenario start and the alert's trigger time.
* An alert that touches an attacker address but comes from a rule the scenario did not list is
  *extra* (not wrong, but worth reading). An alert that touches no attack at all is a *false positive*.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .engine import IP_FIELDS, MISSING
from .models import Alert, iso
from .store import Store

SLACK = 120.0  # seconds of tolerance around a scenario's time window for address-less scenarios


def _alert_ips(store: Store, alert: Alert) -> set[str]:
    ips: set[str] = set()
    for ev in store.events_by_id(alert.event_ids[:200]):
        for f in IP_FIELDS:
            v = ev.get(f)
            if v not in MISSING:
                ips.add(str(v))
    return ips


def _alert_hosts(store: Store, alert: Alert) -> set[str]:
    return {e.host for e in store.events_by_id(alert.event_ids[:50])}


@dataclass
class Result:
    expectations: list[dict]
    extra: list[dict]
    false_positives: list[dict]
    total_alerts: int
    benign_events: int

    @property
    def detected(self) -> int:
        return sum(1 for e in self.expectations if e["detected"])

    @property
    def total(self) -> int:
        return len(self.expectations)

    def to_dict(self) -> dict:
        return {"detected": self.detected, "expected": self.total, "extra_alerts": len(self.extra),
                "false_positives": len(self.false_positives), "total_alerts": self.total_alerts,
                "benign_events": self.benign_events, "expectations": self.expectations,
                "extra": self.extra, "false_positive_alerts": self.false_positives}


def evaluate(store: Store, truth_path: str | Path) -> Result:
    truth = json.loads(Path(truth_path).read_text(encoding="utf-8"))
    alerts = list(store.iter_alerts())
    info = {a.id: (_alert_ips(store, a), _alert_hosts(store, a)) for a in alerts}
    scenarios = truth["scenarios"]

    def involves(a: Alert, sc: dict) -> bool:
        ips, hosts = info[a.id]
        if ips:  # alerts that carry an address must involve an attacker address
            return bool(ips & set(sc["ips"]))
        # address-less alerts (e.g. "user created", "log cleared") are matched by host and time
        return bool(sc.get("host")) and sc["host"] in hosts and \
            (sc["start"] - SLACK <= a.ts_first <= sc["end"] + SLACK)

    expectations, claimed = [], set()
    for sc in scenarios:
        for rule in sc["expect"]:
            hits = [a for a in alerts if a.rule == rule and involves(a, sc)]
            for a in hits:
                claimed.add(a.id)
            first = min(hits, key=lambda a: a.ts_trigger) if hits else None
            expectations.append({
                "scenario": sc["name"], "rule": rule, "detected": bool(hits),
                "seconds_to_detect": round(first.ts_trigger - sc["start"], 1) if first else None,
                "alert_id": first.id if first else None})

    extra, false_pos = [], []
    for a in alerts:
        if a.id in claimed:
            continue
        related = [sc["name"] for sc in scenarios if involves(a, sc)]
        row = {"alert_id": a.id, "rule": a.rule, "level": a.level, "time": iso(a.ts_first),
               "count": a.count, "group": a.group, "scenarios": related}
        (extra if related else false_pos).append(row)

    benign = sum(truth.get("benign_events", {}).values())
    return Result(expectations, extra, false_pos, len(alerts), benign)


def format_report(res: Result) -> str:
    lines = ["Detection results", "-" * 17,
             f"{'scenario':<26}{'expected rule':<30}{'detected':<10}{'time to detect'}"]
    for e in res.expectations:
        ttd = f"{e['seconds_to_detect']:.0f}s" if e["seconds_to_detect"] is not None else "-"
        lines.append(f"{e['scenario']:<26}{e['rule']:<30}{'yes' if e['detected'] else 'MISSED':<10}{ttd}")
    pct = 100 * res.detected / res.total if res.total else 0
    lines += ["", f"Detected {res.detected}/{res.total} expected detections ({pct:.0f}%)",
              f"Total alerts: {res.total_alerts}  |  extra alerts on attacker traffic: {len(res.extra)}"
              f"  |  false positives: {len(res.false_positives)} (on ~{res.benign_events} benign events)"]
    for ex in res.extra:
        lines.append(f"  extra: {ex['rule']} ({ex['level']}) at {ex['time']} during {', '.join(ex['scenarios'])}")
    for fp in res.false_positives:
        lines.append(f"  FALSE POSITIVE: {fp['rule']} at {fp['time']} group={fp['group']}")
    return "\n".join(lines)
