"""End-to-end: simulate -> ingest -> detect -> evaluate, through the real CLI."""
import json

import pytest

from minisiem.cli import main
from minisiem.evaluate import evaluate
from minisiem.store import Store

LOGS = [("nginx", "nginx_access.log"), ("ssh", "auth.log"), ("windows", "windows_security.jsonl")]


def pipeline(tmp_path, seed, attacks=True, rules="rules"):
    logs = tmp_path / f"logs{seed}{'a' if attacks else 'b'}"
    db = str(tmp_path / f"s{seed}{'a' if attacks else 'b'}.db")
    assert main(["simulate", "--out", str(logs), "--seed", str(seed)] + ([] if attacks else ["--no-attacks"])) == 0
    for typ, name in LOGS:
        assert main(["ingest", "--type", typ, str(logs / name), "--year", "2026", "--db", db]) == 0
    assert main(["detect", "--rules", rules, "--db", db]) == 0
    return db, logs / "truth.json"


@pytest.mark.parametrize("seed", [1, 2, 3, 7, 11, 42])
def test_every_injected_attack_is_detected_with_no_false_positives(tmp_path, seed):
    db, truth = pipeline(tmp_path, seed)
    res = evaluate(Store(db), truth)
    missed = [(e["scenario"], e["rule"]) for e in res.expectations if not e["detected"]]
    assert missed == []
    assert res.false_positives == []
    assert res.total == 28


@pytest.mark.parametrize("seed", [1, 2, 3, 7, 11, 42])
def test_normal_traffic_alone_raises_no_alerts(tmp_path, seed):
    db, _ = pipeline(tmp_path, seed, attacks=False)
    assert list(Store(db).iter_alerts()) == []


def test_ingest_is_idempotent_and_detection_is_repeatable(tmp_path):
    db, truth = pipeline(tmp_path, 7)
    store = Store(db)
    n_events = store.count_events()
    first = [(a.rule, a.count, a.ts_first) for a in store.iter_alerts()]
    logs = truth.parent
    for typ, name in LOGS:
        main(["ingest", "--type", typ, str(logs / name), "--year", "2026", "--db", db])
    main(["detect", "--rules", "rules", "--db", db])
    store = Store(db)
    assert store.count_events() == n_events
    assert [(a.rule, a.count, a.ts_first) for a in store.iter_alerts()] == first


def test_wrong_type_is_reported_not_silently_ignored(tmp_path, capsys):
    logs = tmp_path / "l"
    main(["simulate", "--out", str(logs)])
    code = main(["ingest", "--type", "windows", str(logs / "nginx_access.log"), "--db", str(tmp_path / "x.db")])
    assert code == 1
    assert "not understood" in capsys.readouterr().out


def test_evaluate_cli_exit_code_and_json(tmp_path, capsys):
    db, truth = pipeline(tmp_path, 7)
    capsys.readouterr()  # discard the output of simulate/ingest/detect
    assert main(["evaluate", "--db", db, "--truth", str(truth), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["detected"] == data["expected"] == 28 and data["false_positives"] == 0


def test_evaluator_actually_notices_a_missing_rule(tmp_path):
    """Guard against an evaluator that can only say 'yes': remove one rule and expect exactly that miss."""
    import shutil
    rules = tmp_path / "rules"
    shutil.copytree("rules", rules)
    f = rules / "web" / "web_attacks.yml"
    docs = f.read_text().split("\n---\n")
    kept = [d for d in docs if "name: web_xss" not in d]
    assert len(kept) == len(docs) - 1
    f.write_text("\n---\n".join(kept))
    db, truth = pipeline(tmp_path, 7, rules=str(rules))
    res = evaluate(Store(db), truth)
    assert [(e["scenario"], e["rule"]) for e in res.expectations if not e["detected"]] == [("web_xss", "web_xss")]
    assert res.detected == 27
