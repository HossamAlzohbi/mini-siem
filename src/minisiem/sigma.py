"""A compact Sigma rule engine.

Implemented (a deliberate subset of the Sigma specification):

* ``detection`` blocks: named selections (maps, lists of maps, keyword lists) and a
  ``condition`` with ``and`` / ``or`` / ``not``, parentheses, ``1 of X*``, ``all of X*``,
  ``1 of them`` and ``all of them``.
* Value modifiers: ``contains``, ``startswith``, ``endswith``, ``all``, ``re``, ``cidr``,
  ``lt``/``lte``/``gt``/``gte``, ``exists``. Plain values support ``*`` and ``?`` wildcards.
  String matching is case-insensitive (the Sigma default), ``re`` is case-sensitive unless ``(?i)``.
* Correlation rules (Sigma correlation spec): ``event_count``, ``value_count``, ``temporal``,
  ``temporal_ordered``, ``group-by``, ``aliases``, ``timespan``, conditions ``gt``/``gte``/``eq``,
  and correlations that reference other correlations.

Not implemented: ``|count()`` style aggregations (use correlation instead), ``base64``/``windash``
modifiers, field-name mapping pipelines, ``timeframe`` and ``lt``/``lte`` correlation conditions.
Unsupported constructs raise ``RuleError`` at load time instead of silently never matching.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .models import LEVELS, Event
from .timeutil import parse_timespan


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------
# Logsource mapping
# --------------------------------------------------------------------------
# Which MiniSIEM event source does a Sigma ``logsource`` refer to?
LOGSOURCE_MAP = {
    "webserver": "nginx", "nginx": "nginx", "apache": "nginx",
    "sshd": "ssh", "ssh": "ssh",
    "windows": "windows", "security": "windows", "system": "windows", "sysmon": "windows",
    "process_creation": "windows",
}
# Categories that need an extra event filter on top of the source.
CATEGORY_EVENT_IDS = {"process_creation": {1, 4688}}


def resolve_logsource(ls: dict[str, Any]) -> tuple[str, set[int] | None]:
    for key in ("service", "category", "product"):
        value = str(ls.get(key, "")).lower()
        if value in LOGSOURCE_MAP:
            category = str(ls.get("category", "")).lower()
            return LOGSOURCE_MAP[value], CATEGORY_EVENT_IDS.get(category)
    raise RuleError(f"unknown logsource {ls!r}; supported: {sorted(LOGSOURCE_MAP)}")


# --------------------------------------------------------------------------
# Value matching
# --------------------------------------------------------------------------
def _wildcard_to_regex(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and pattern[i + 1:i + 2] in ("*", "?"):
            out.append(re.escape(pattern[i + 1]))
            i += 2
        elif c == "\\" and pattern[i + 1:i + 2] == "\\" and pattern[i + 2:i + 3] in ("*", "?"):
            out.append(re.escape("\\"))
            i += 2
        elif c == "*":
            out.append(".*")
            i += 1
        elif c == "?":
            out.append(".")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _s(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def _make_value_test(mods: list[str], value: Any) -> Callable[[Any], bool]:
    """Return a predicate on a single field value for one rule value."""
    if value is None:
        return lambda fv: fv is None or fv == ""
    if "re" in mods:
        try:
            rx = re.compile(str(value), re.S)
        except re.error as exc:
            raise RuleError(f"invalid regex {value!r}: {exc}") from exc
        return lambda fv: fv is not None and rx.search(_s(fv)) is not None
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise RuleError(f"invalid CIDR {value!r}") from exc

        def cidr(fv: Any) -> bool:
            try:
                return ipaddress.ip_address(_s(fv)) in net
            except ValueError:
                return False
        return cidr
    for op, fn in (("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b),
                   ("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b)):
        if op in mods:
            limit = float(value)

            def cmp(fv: Any, fn=fn, limit=limit) -> bool:
                try:
                    return fn(float(fv), limit)
                except (TypeError, ValueError):
                    return False
            return cmp

    needle = _s(value).lower()
    if "contains" in mods:
        if "*" in needle or "?" in needle:
            rx = re.compile(".*" + _wildcard_to_regex(needle) + ".*", re.S)
            return lambda fv: fv is not None and rx.fullmatch(_s(fv).lower()) is not None
        return lambda fv: fv is not None and needle in _s(fv).lower()
    if "startswith" in mods:
        return lambda fv: fv is not None and _s(fv).lower().startswith(needle)
    if "endswith" in mods:
        return lambda fv: fv is not None and _s(fv).lower().endswith(needle)
    if "*" in needle or "?" in needle:
        rx = re.compile(_wildcard_to_regex(_s(value).lower()), re.S)
        return lambda fv: fv is not None and rx.fullmatch(_s(fv).lower()) is not None
    return lambda fv: fv is not None and _s(fv).lower() == needle


SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "cidr",
                  "lt", "lte", "gt", "gte", "exists"}


def _compile_field(key: str, expected: Any) -> Callable[[Event], bool]:
    name, *mods = key.split("|")
    unknown = [m for m in mods if m not in SUPPORTED_MODS]
    if unknown:
        raise RuleError(f"unsupported modifier(s) {unknown} on field {name!r}")
    if "exists" in mods:
        want = bool(expected)
        return lambda ev: (ev.get(name) not in (None, "")) == want
    values = expected if isinstance(expected, list) else [expected]
    tests = [_make_value_test(mods, v) for v in values]
    combine_all = "all" in mods
    if combine_all:
        return lambda ev: all(t(ev.get(name)) for t in tests)
    return lambda ev: any(t(ev.get(name)) for t in tests)


def _compile_keywords(words: list[Any]) -> Callable[[Event], bool]:
    tests = [_make_value_test(["contains"], w) for w in words]
    return lambda ev: any(t(ev.raw) for t in tests)


def _compile_selection(sel: Any) -> Callable[[Event], bool]:
    if isinstance(sel, dict):
        parts = [_compile_field(k, v) for k, v in sel.items()]
        return lambda ev: all(p(ev) for p in parts)
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            alts = [_compile_selection(x) for x in sel]
            return lambda ev: any(a(ev) for a in alts)
        if all(not isinstance(x, (dict, list)) for x in sel):
            return _compile_keywords(sel)
    raise RuleError(f"unsupported selection {sel!r}")


# --------------------------------------------------------------------------
# Condition parser
# --------------------------------------------------------------------------
_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _Parser:
    def __init__(self, text: str, names: list[str]):
        if "|" in text:
            raise RuleError("aggregation with '|' in a condition is not supported; use a correlation rule")
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.names = names

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise RuleError("unexpected end of condition")
        self.pos += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise RuleError(f"unexpected token {self.peek()!r} in condition")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek() is not None and self.peek().lower() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while self.peek() is not None and self.peek().lower() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self):
        if self.peek() is not None and self.peek().lower() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok == "(":
            node = self.or_expr()
            if self.peek() != ")":
                raise RuleError("missing ')' in condition")
            self.take()
            return node
        nxt = self.peek()
        if tok.lower() in ("1", "all") and nxt is not None and nxt.lower() == "of":
            self.take()
            target = self.take()
            if target.lower() == "them":
                chosen = list(self.names)
            else:
                rx = re.compile("^" + re.escape(target).replace(r"\*", ".*") + "$")
                chosen = [n for n in self.names if rx.match(n)]
            if not chosen:
                raise RuleError(f"'{tok} of {target}' matches no selection")
            return ("any" if tok == "1" else "allof", chosen)
        if tok not in self.names:
            raise RuleError(f"condition references unknown selection {tok!r}")
        return ("sel", tok)


def _eval(node, ev: Event, sels: dict[str, Callable[[Event], bool]], cache: dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "sel":
        name = node[1]
        if name not in cache:
            cache[name] = sels[name](ev)
        return cache[name]
    if kind == "and":
        return _eval(node[1], ev, sels, cache) and _eval(node[2], ev, sels, cache)
    if kind == "or":
        return _eval(node[1], ev, sels, cache) or _eval(node[2], ev, sels, cache)
    if kind == "not":
        return not _eval(node[1], ev, sels, cache)
    names = node[1]
    results = (_eval(("sel", n), ev, sels, cache) for n in names)
    return any(results) if kind == "any" else all(results)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
@dataclass
class Rule:
    name: str
    title: str
    level: str
    description: str
    tags: list[str]
    path: str
    alert: bool | None = None  # explicit override of the "referenced rules stay silent" default
    # detection rules
    source: str | None = None
    event_ids: set[int] | None = None
    test: Callable[[Event], bool] | None = None
    # correlation rules
    corr: dict[str, Any] | None = None

    @property
    def is_correlation(self) -> bool:
        return self.corr is not None

    def matches(self, ev: Event) -> bool:
        assert self.test is not None
        if ev.source != self.source:
            return False
        if self.event_ids is not None and ev.get("EventID") not in self.event_ids:
            return False
        return self.test(ev)


def _compile_detection(det: dict[str, Any]) -> Callable[[Event], bool]:
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError("detection needs a 'condition'")
    cond = det["condition"]
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    sels = {k: _compile_selection(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    if not sels:
        raise RuleError("detection has no selections")
    tree = _Parser(str(cond), list(sels)).parse()
    return lambda ev: _eval(tree, ev, sels, {})


_COND_OPS = {
    "gt": lambda n, t: n > t,
    "gte": lambda n, t: n >= t,
    "eq": lambda n, t: n == t,
}
CORR_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered"}


def _parse_correlation(doc: dict[str, Any], name: str) -> dict[str, Any]:
    c = doc["correlation"]
    ctype = c.get("type")
    if ctype not in CORR_TYPES:
        raise RuleError(f"correlation type must be one of {sorted(CORR_TYPES)}, got {ctype!r}")
    rules = c.get("rules")
    if not rules or not isinstance(rules, list):
        raise RuleError("correlation needs a non-empty 'rules' list")
    out: dict[str, Any] = {
        "type": ctype,
        "rules": [str(r) for r in rules],
        "group_by": list(c.get("group-by", [])),
        "timespan": parse_timespan(c.get("timespan", "")),
        "aliases": {a: {str(k): v for k, v in m.items()} for a, m in (c.get("aliases") or {}).items()},
        "generate": bool(c.get("generate", False)),
    }
    if ctype in ("event_count", "value_count"):
        cond = c.get("condition") or {}
        ops = [k for k in cond if k in _COND_OPS]
        bad = [k for k in cond if k not in _COND_OPS and k != "field"]
        if bad:
            raise RuleError(f"unsupported correlation condition operator(s) {bad}; supported: gt, gte, eq")
        if len(ops) != 1:
            raise RuleError("correlation condition needs exactly one of gt / gte / eq")
        out["op"], out["threshold"] = ops[0], int(cond[ops[0]])
        if ctype == "value_count":
            if not cond.get("field"):
                raise RuleError("value_count condition needs 'field'")
            out["field"] = cond["field"]
    if ctype == "event_count" and len(out["group_by"]) == 0:
        pass  # a global count is allowed
    return out


def load_rule_docs(path: Path) -> list[Rule]:
    rules: list[Rule] = []
    try:
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}: invalid YAML: {exc}") from exc
    for doc in docs:
        try:
            rules.append(_build_rule(doc, str(path)))
        except RuleError as exc:
            raise RuleError(f"{path}: {exc}") from exc
    return rules


def _build_rule(doc: dict[str, Any], path: str) -> Rule:
    if not isinstance(doc, dict):
        raise RuleError("rule must be a YAML mapping")
    title = doc.get("title")
    if not title:
        raise RuleError("rule needs a 'title'")
    name = str(doc.get("name") or doc.get("id") or "").strip()
    if not name:
        raise RuleError(f"rule {title!r} needs a 'name' (or 'id')")
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        raise RuleError(f"level must be one of {LEVELS}, got {level!r}")
    rule = Rule(name=name, title=title, level=level, description=str(doc.get("description", "")).strip(),
                tags=[str(t) for t in doc.get("tags", [])], path=path, alert=doc.get("alert"))
    if "correlation" in doc:
        rule.corr = _parse_correlation(doc, name)
        return rule
    if "detection" not in doc or "logsource" not in doc:
        raise RuleError(f"rule {name!r} needs 'logsource' and 'detection' (or 'correlation')")
    rule.source, rule.event_ids = resolve_logsource(doc["logsource"])
    rule.test = _compile_detection(doc["detection"])
    return rule


def load_rules(directory: str | Path) -> list[Rule]:
    base = Path(directory)
    files = sorted(list(base.rglob("*.yml")) + list(base.rglob("*.yaml")))
    if not files:
        raise RuleError(f"no rule files found in {base}")
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for f in files:
        for r in load_rule_docs(f):
            if r.name in seen:
                raise RuleError(f"duplicate rule name {r.name!r} in {f} and {seen[r.name]}")
            seen[r.name] = str(f)
            rules.append(r)
    names = {r.name for r in rules}
    for r in rules:
        if r.corr:
            missing = [x for x in r.corr["rules"] if x not in names]
            if missing:
                raise RuleError(f"{r.path}: correlation {r.name!r} references unknown rule(s) {missing}")
    return rules
