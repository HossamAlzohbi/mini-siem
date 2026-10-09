"""Detection engine: runs rules over events and builds alerts.

Pipeline
--------
1. Every plain rule is evaluated against the events of its log source -> ``Match`` objects.
2. Correlation rules consume the matches of the rules they reference (which may themselves be
   correlations) in dependency order and produce new matches.
3. Rules that are not silenced produce alerts. A rule referenced by a correlation stays silent
   unless the rule sets ``alert: true`` or the correlation sets ``generate: true`` (Sigma semantics).
"""
from __future__ import annotations

from collections import Counter, deque
from typing import Callable, Iterable

from .models import Alert, Event, Match
from .sigma import _COND_OPS, Rule, RuleError

# Single-event alerts from the same rule and entity are merged while the gap between
# consecutive hits stays below this many seconds (prevents one alert per request in a scan).
SUPPRESS_GAP = 300.0
IP_FIELDS = ("c-ip", "src_ip", "IpAddress")
MISSING = (None, "", "-")


def entity_of(ev: Event) -> str:
    for f in IP_FIELDS:
        v = ev.get(f)
        if v not in MISSING:
            return str(v)
    return ev.host


# ----------------------------------------------------------------------
# Window state machines for the different correlation types
# ----------------------------------------------------------------------
class _CountState:
    def __init__(self, cond: Callable[[int], bool]):
        self.n, self.cond = 0, cond

    def add(self, m: Match) -> None:
        self.n += 1

    def remove(self, m: Match) -> None:
        self.n -= 1

    def ok(self) -> bool:
        return self.cond(self.n)


class _DistinctState:
    def __init__(self, cond: Callable[[int], bool], field: str):
        self.c: Counter = Counter()
        self.cond, self.field = cond, field

    def _v(self, m: Match):
        v = m.fields.get(self.field)
        return None if v in MISSING else str(v)

    def add(self, m: Match) -> None:
        v = self._v(m)
        if v is not None:
            self.c[v] += 1

    def remove(self, m: Match) -> None:
        v = self._v(m)
        if v is not None:
            self.c[v] -= 1
            if self.c[v] <= 0:
                del self.c[v]

    def ok(self) -> bool:
        return self.cond(len(self.c))


class _TemporalState:
    def __init__(self, refs: list[str]):
        self.refs, self.c = refs, Counter()

    def add(self, m: Match) -> None:
        self.c[m.rule] += 1

    def remove(self, m: Match) -> None:
        self.c[m.rule] -= 1

    def ok(self) -> bool:
        return all(self.c[r] > 0 for r in self.refs)


class _Burst:
    """An open correlation alert that keeps growing while hits stay within the timespan."""

    def __init__(self, window: list[Match], trigger: float):
        self.matches = list(window)
        self.trigger = trigger

    @property
    def last_ts(self) -> float:
        return self.matches[-1].ts


def _bursts(matches: list[Match], timespan: float, state) -> list[_Burst]:
    done: list[_Burst] = []
    window: deque[Match] = deque()
    active: _Burst | None = None
    for m in matches:
        if active is not None and m.ts - active.last_ts > timespan:
            done.append(active)
            active = None
        while window and m.ts - window[0].ts > timespan:
            state.remove(window.popleft())
        window.append(m)
        state.add(m)
        if active is not None:
            active.matches.append(m)
        elif state.ok():
            active = _Burst(list(window), m.ts)
    if active is not None:
        done.append(active)
    return done


def _ordered_chains(matches: list[Match], refs: list[str], timespan: float) -> list[_Burst]:
    """temporal_ordered: refs[0] then refs[1] ... each within ``timespan`` of the first."""
    done: list[_Burst] = []
    blocked_until = float("-inf")
    for start in (m for m in matches if m.rule == refs[0]):
        if start.ts <= blocked_until:
            continue
        chain, prev = [start], start
        for ref in refs[1:]:
            nxt = next((m for m in matches
                        if m.rule == ref and m.ts >= prev.ts and m.ts - start.ts <= timespan
                        and m is not prev), None)
            if nxt is None:
                chain = []
                break
            chain.append(nxt)
            prev = nxt
        if chain:
            done.append(_Burst(chain, chain[-1].ts))
            blocked_until = chain[-1].ts
    return done


# ----------------------------------------------------------------------
class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self.by_name = {r.name: r for r in rules}
        self.order = self._toposort()
        self._bursts: dict[str, list[tuple[dict, _Burst, list[int]]]] = {}

    def _toposort(self) -> list[Rule]:
        ordered: list[Rule] = []
        state: dict[str, int] = {}

        def visit(r: Rule, trail: tuple[str, ...]) -> None:
            if state.get(r.name) == 2:
                return
            if state.get(r.name) == 1:
                raise RuleError(f"correlation cycle: {' -> '.join(trail + (r.name,))}")
            state[r.name] = 1
            if r.corr:
                for ref in r.corr["rules"]:
                    visit(self.by_name[ref], trail + (r.name,))
            state[r.name] = 2
            ordered.append(r)

        for r in self.rules:
            visit(r, ())
        return ordered

    def silenced(self) -> set[str]:
        """Names of rules that only feed correlations and should not alert on their own."""
        referenced: dict[str, bool] = {}
        for r in self.rules:
            if r.corr:
                for ref in r.corr["rules"]:
                    referenced[ref] = referenced.get(ref, False) or r.corr["generate"]
        return {n for n, generated in referenced.items()
                if not generated and self.by_name[n].alert is not True}

    # ------------------------------------------------------------------
    def run(self, events: Iterable[Event]) -> list[Alert]:
        events = sorted(events, key=lambda e: (e.ts, e.id or 0))
        by_source: dict[str, list[Event]] = {}
        for e in events:
            by_source.setdefault(e.source, []).append(e)

        self._bursts = {}
        matches: dict[str, list[Match]] = {}
        hit_events: dict[str, list[Event]] = {}
        for r in self.order:
            if r.is_correlation:
                matches[r.name] = self._correlate(r, matches)
            else:
                hits = [e for e in by_source.get(r.source or "", []) if r.matches(e)]
                hit_events[r.name] = hits
                matches[r.name] = [Match(e.ts, e.fields, [e.id or 0], r.name) for e in hits]

        silent = self.silenced()
        alerts: list[Alert] = []
        for r in self.rules:
            if r.name in silent or r.alert is False:
                continue
            if r.is_correlation:
                alerts += self._correlation_alerts(r)
            else:
                alerts += self._event_alerts(r, hit_events[r.name])
        alerts.sort(key=lambda a: (a.ts_first, a.rule))
        return alerts

    # ------------------------------------------------------------------
    def _group_key(self, rule: Rule, m: Match):
        c = rule.corr
        names = []
        for g in c["group_by"]:
            names.append(c["aliases"].get(g, {}).get(m.rule, g))
        vals = [m.fields.get(n) for n in names]
        if any(v in MISSING for v in vals):
            return None
        return tuple(str(v) for v in vals)

    def _correlate(self, rule: Rule, matches: dict[str, list[Match]]) -> list[Match]:
        c = rule.corr
        merged = sorted((m for ref in c["rules"] for m in matches[ref]), key=lambda m: m.ts)
        groups: dict[tuple, list[Match]] = {}
        for m in merged:
            key = self._group_key(rule, m)
            if key is not None:
                groups.setdefault(key, []).append(m)

        out: list[Match] = []
        self._bursts[rule.name] = []
        for key, ms in groups.items():
            if c["type"] == "event_count":
                bursts = _bursts(ms, c["timespan"], _CountState(lambda n, c=c: _COND(c, n)))
            elif c["type"] == "value_count":
                bursts = _bursts(ms, c["timespan"],
                                 _DistinctState(lambda n, c=c: _COND(c, n), c["field"]))
            elif c["type"] == "temporal":
                bursts = _bursts(ms, c["timespan"], _TemporalState(c["rules"]))
            else:
                bursts = _ordered_chains(ms, c["rules"], c["timespan"])
            group = dict(zip(c["group_by"], key))
            for b in bursts:
                ids = [i for m in b.matches for i in m.event_ids]
                self._bursts[rule.name].append((group, b, ids))
                out.append(Match(b.trigger, dict(group), ids, rule.name))
        out.sort(key=lambda m: m.ts)
        return out

    def _correlation_alerts(self, rule: Rule) -> list[Alert]:
        alerts = []
        for group, b, ids in self._bursts.get(rule.name, []):
            uniq = list(dict.fromkeys(ids))
            alerts.append(Alert(
                rule=rule.name, title=rule.title, level=rule.level, description=rule.description,
                tags=rule.tags, kind="correlation", ts_first=b.matches[0].ts, ts_last=b.matches[-1].ts,
                ts_trigger=b.trigger, count=len(uniq), group=group, event_ids=uniq))
        return alerts

    def _event_alerts(self, rule: Rule, hits: list[Event]) -> list[Alert]:
        """Merge single-event hits per entity into bursts so one scan = one alert."""
        per_entity: dict[str, list[Event]] = {}
        for e in hits:
            per_entity.setdefault(entity_of(e), []).append(e)
        alerts = []
        for entity, evs in per_entity.items():
            cur: list[Event] = []
            for e in evs:
                if cur and e.ts - cur[-1].ts > SUPPRESS_GAP:
                    alerts.append(self._make_event_alert(rule, entity, cur))
                    cur = []
                cur.append(e)
            if cur:
                alerts.append(self._make_event_alert(rule, entity, cur))
        return alerts

    @staticmethod
    def _make_event_alert(rule: Rule, entity: str, evs: list[Event]) -> Alert:
        return Alert(rule=rule.name, title=rule.title, level=rule.level, description=rule.description,
                     tags=rule.tags, kind="rule", ts_first=evs[0].ts, ts_last=evs[-1].ts,
                     ts_trigger=evs[0].ts, count=len(evs), group={"entity": entity},
                     event_ids=[e.id or 0 for e in evs])


def _COND(c: dict, n: int) -> bool:
    return _COND_OPS[c["op"]](n, c["threshold"])
