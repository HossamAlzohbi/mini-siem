"""Command line interface: ``minisiem <command>``."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import timezone, timedelta
from pathlib import Path

from . import __version__
from .engine import Engine
from .evaluate import evaluate, format_report
from .models import LEVELS, iso
from .parsers import PARSERS
from .sigma import RuleError, load_rules
from .simulate import generate
from .store import Store


def default_rules_dir() -> str:
    for cand in (Path("rules"), Path(__file__).resolve().parents[2] / "rules"):
        if cand.is_dir():
            return str(cand)
    return "rules"


def _tz(text: str) -> timezone:
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if not m:
        raise argparse.ArgumentTypeError("use an offset like +02:00")
    delta = timedelta(hours=int(m[2]), minutes=int(m[3]))
    return timezone(delta if m[1] == "+" else -delta)


def cmd_ingest(args) -> int:
    store = Store(args.db)
    total_ok = total_bad = total_dupe = 0
    for path in args.paths:
        if not Path(path).is_file():
            print(f"error: {path} is not a file", file=sys.stderr)
            return 2
        origin = str(Path(path).resolve())
        batch, bad = [], 0
        for lineno, _raw, ev in PARSERS[args.type](path, host=args.host, year=args.year, tz=args.tz):
            if ev is None:
                bad += 1
                continue
            batch.append((origin, lineno, ev))
        inserted, dupes = store.add_events(batch)
        total_ok += inserted
        total_bad += bad
        total_dupe += dupes
        print(f"{path}: {inserted} events stored, {dupes} already present, {bad} lines not understood")
    if total_ok == 0 and total_bad and not total_dupe:
        print("warning: nothing was parsed - is --type correct?", file=sys.stderr)
        return 1
    return 0


def cmd_detect(args) -> int:
    try:
        rules = load_rules(args.rules or default_rules_dir())
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2
    store = Store(args.db)
    alerts = Engine(rules).run(store.iter_events())
    store.replace_alerts(alerts)
    by_level = Counter(a.level for a in alerts)
    print(f"{len(rules)} rules, {store.count_events()} events -> {len(alerts)} alerts")
    for lvl in reversed(LEVELS):
        if by_level[lvl]:
            print(f"  {lvl:<14}{by_level[lvl]}")
    return 0


def cmd_alerts(args) -> int:
    store = Store(args.db)
    floor = LEVELS.index(args.min_level)
    rows = [a for a in store.iter_alerts() if LEVELS.index(a.level) >= floor]
    if args.json:
        print(json.dumps([{**a.__dict__, "time": iso(a.ts_first)} for a in rows], indent=2))
        return 0
    print(f"{'id':>4}  {'time (UTC)':<20}{'level':<10}{'rule':<28}{'events':>6}  group")
    for a in rows:
        group = ", ".join(f"{k}={v}" for k, v in a.group.items())
        print(f"{a.id:>4}  {iso(a.ts_first):<20}{a.level:<10}{a.rule:<28}{a.count:>6}  {group}")
    print(f"{len(rows)} alerts")
    return 0


def cmd_rules(args) -> int:
    try:
        rules = load_rules(args.rules or default_rules_dir())
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2
    silent = Engine(rules).silenced()
    if args.action == "validate":
        print(f"OK: {len(rules)} rules are valid")
        return 0
    print(f"{'name':<28}{'level':<14}{'kind':<13}{'alerts?':<9}tags")
    for r in rules:
        kind = r.corr["type"] if r.corr else "rule"
        print(f"{r.name:<28}{r.level:<14}{kind:<13}{'no' if r.name in silent else 'yes':<9}{', '.join(r.tags)}")
    return 0


def cmd_simulate(args) -> int:
    truth = generate(args.out, seed=args.seed, attacks=not args.no_attacks)
    print(f"wrote logs and truth.json to {args.out} "
          f"({len(truth['scenarios'])} attack scenarios, seed {truth['seed']})")
    return 0


def cmd_evaluate(args) -> int:
    res = evaluate(Store(args.db), args.truth)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(format_report(res))
    return 0 if res.detected == res.total and not res.false_positives else 1


def cmd_serve(args) -> int:
    from .dashboard import serve
    return serve(args.db, args.host, args.port)


def cmd_demo(args) -> int:
    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    db = out / "demo.db"
    if db.exists():
        db.unlink()
    generate(out, seed=args.seed)
    store = Store(db)
    for typ, name in (("nginx", "nginx_access.log"), ("ssh", "auth.log"), ("windows", "windows_security.jsonl")):
        batch = [(name, n, ev) for n, _r, ev in PARSERS[typ](str(out / name), host="", year=2026, tz=timezone.utc)
                 if ev]
        store.add_events(batch)
    rules = load_rules(args.rules or default_rules_dir())
    store.replace_alerts(Engine(rules).run(store.iter_events()))
    print(f"{store.count_events()} events, {len(list(store.iter_alerts()))} alerts stored in {db}\n")
    res = evaluate(store, out / "truth.json")
    print(format_report(res))
    store.close()
    if args.serve:
        from .dashboard import serve
        return serve(str(db), "127.0.0.1", args.port)
    print(f"\nOpen the dashboard with:  minisiem serve --db {db}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="minisiem", description="A small, readable SIEM for learning detection engineering.")
    p.add_argument("--version", action="version", version=f"minisiem {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def db_arg(sp):
        sp.add_argument("--db", default="minisiem.db", help="SQLite database file (default: minisiem.db)")

    sp = sub.add_parser("ingest", help="parse log files into the database")
    sp.add_argument("--type", required=True, choices=sorted(PARSERS), help="log format")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--host", default="", help="host name to record (default: taken from the log)")
    sp.add_argument("--year", type=int, default=None, help="year for syslog timestamps that carry none")
    sp.add_argument("--tz", type=_tz, default=timezone.utc, help="UTC offset of syslog timestamps, e.g. +02:00")
    db_arg(sp)
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("detect", help="run the rules and (re)build the alerts")
    sp.add_argument("--rules", help="rules directory (default: ./rules)")
    db_arg(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("alerts", help="list alerts")
    sp.add_argument("--min-level", choices=LEVELS, default="informational")
    sp.add_argument("--json", action="store_true")
    db_arg(sp)
    sp.set_defaults(func=cmd_alerts)

    sp = sub.add_parser("rules", help="list or validate rules")
    sp.add_argument("action", choices=["list", "validate"])
    sp.add_argument("--rules")
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser("serve", help="start the dashboard (localhost only by default)")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8765)
    db_arg(sp)
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("simulate", help="write synthetic logs with attacks and a ground-truth file")
    sp.add_argument("--out", default="demo")
    sp.add_argument("--seed", type=int, default=7)
    sp.add_argument("--no-attacks", action="store_true", help="benign traffic only")
    sp.set_defaults(func=cmd_simulate)

    sp = sub.add_parser("evaluate", help="score alerts against a truth.json from `simulate`")
    sp.add_argument("--truth", required=True)
    sp.add_argument("--json", action="store_true")
    db_arg(sp)
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("demo", help="simulate -> ingest -> detect -> evaluate in one go")
    sp.add_argument("--dir", default="demo")
    sp.add_argument("--seed", type=int, default=7)
    sp.add_argument("--rules")
    sp.add_argument("--serve", action="store_true", help="start the dashboard afterwards")
    sp.add_argument("--port", type=int, default=8765)
    sp.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
