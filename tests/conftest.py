import itertools
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from minisiem.models import Event  # noqa: E402
from minisiem.sigma import load_rules  # noqa: E402

_ids = itertools.count(1)
T0 = 1_790_000_000.0


def ev(ts, source="ssh", host="h1", raw="x", **fields):
    return Event(ts=T0 + ts, source=source, host=host, fields=fields, raw=raw, id=next(_ids))


def ssh_fail(ts, ip="203.0.113.5", user="root"):
    return ev(ts, "ssh", action="failed_password", src_ip=ip, user=user)


def ssh_ok(ts, ip="203.0.113.5", user="root"):
    return ev(ts, "ssh", action="accepted", src_ip=ip, user=user)


@pytest.fixture
def rules_from(tmp_path):
    def _make(text: str):
        (tmp_path / "r.yml").write_text(text, encoding="utf-8")
        return load_rules(tmp_path)
    return _make


@pytest.fixture(scope="session")
def project_rules():
    return load_rules(ROOT / "rules")
