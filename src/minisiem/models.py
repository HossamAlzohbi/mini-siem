"""Core data structures shared by parsers, storage, rules and the dashboard."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

LEVELS = ["informational", "low", "medium", "high", "critical"]


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Event:
    """One normalised log event.

    ``fields`` uses Sigma-style field names so community rules can run on it:
    web events use the Sigma webserver taxonomy (``c-ip``, ``cs-uri-stem`` ...),
    Windows events use ``EventID`` plus the flattened ``EventData`` fields.
    """

    ts: float
    source: str  # "nginx" | "ssh" | "windows"
    host: str
    fields: dict[str, Any]
    raw: str
    id: int | None = None
    _lower: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    def get(self, name: str) -> Any:
        if name in self.fields:
            return self.fields[name]
        if self._lower is None:
            self._lower = {k.lower(): v for k, v in self.fields.items()}
        return self._lower.get(name.lower())


@dataclass
class Match:
    """A rule hit that correlation rules can consume.

    For a plain rule this is one event; for a correlation rule it is one
    correlation alert (``fields`` then holds the group-by values).
    """

    ts: float
    fields: dict[str, Any]
    event_ids: list[int]
    rule: str


@dataclass
class Alert:
    rule: str
    title: str
    level: str
    description: str
    tags: list[str]
    kind: str  # "rule" | "correlation"
    ts_first: float
    ts_last: float
    ts_trigger: float
    count: int
    group: dict[str, Any]
    event_ids: list[int]
    id: int | None = None
