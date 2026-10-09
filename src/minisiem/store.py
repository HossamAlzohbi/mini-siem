"""SQLite storage for events and alerts."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator

from .models import Alert, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    host TEXT NOT NULL,
    fields TEXT NOT NULL,
    raw TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source, ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule TEXT NOT NULL,
    title TEXT NOT NULL,
    level TEXT NOT NULL,
    description TEXT NOT NULL,
    tags TEXT NOT NULL,
    kind TEXT NOT NULL,
    ts_first REAL NOT NULL,
    ts_last REAL NOT NULL,
    ts_trigger REAL NOT NULL,
    count INTEGER NOT NULL,
    grp TEXT NOT NULL,
    event_ids TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_first);
"""

MAX_EVENT_IDS_PER_ALERT = 1000


class Store:
    def __init__(self, path: str | Path = "minisiem.db", readonly: bool = False):
        self.path = str(path)
        if readonly:
            if not Path(self.path).is_file():
                raise FileNotFoundError(self.path)
            self.db = sqlite3.connect(f"file:{Path(self.path).resolve()}?mode=ro", uri=True,
                                      check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            return
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ---- events -------------------------------------------------------
    @staticmethod
    def _key(source: str, origin: str, lineno: int, raw: str) -> str:
        return hashlib.sha1(f"{source}|{origin}|{lineno}|{raw}".encode("utf-8", "replace")).hexdigest()

    def add_events(self, rows: Iterable[tuple[str, int, Event]]) -> tuple[int, int]:
        """Insert (origin, lineno, event) rows. Returns (inserted, duplicates)."""
        inserted = dupes = 0
        cur = self.db.cursor()
        for origin, lineno, ev in rows:
            cur.execute(
                "INSERT OR IGNORE INTO events(ts, source, host, fields, raw, dedupe_key) VALUES (?,?,?,?,?,?)",
                (ev.ts, ev.source, ev.host, json.dumps(ev.fields), ev.raw,
                 self._key(ev.source, origin, lineno, ev.raw)),
            )
            if cur.rowcount:
                inserted += 1
            else:
                dupes += 1
        self.db.commit()
        return inserted, dupes

    @staticmethod
    def _event(row: sqlite3.Row) -> Event:
        return Event(ts=row["ts"], source=row["source"], host=row["host"],
                     fields=json.loads(row["fields"]), raw=row["raw"], id=row["id"])

    def iter_events(self, source: str | None = None) -> Iterator[Event]:
        sql, args = "SELECT * FROM events", []
        if source:
            sql += " WHERE source = ?"
            args.append(source)
        sql += " ORDER BY ts, id"
        for row in self.db.execute(sql, args):
            yield self._event(row)

    def events_by_id(self, ids: list[int]) -> list[Event]:
        out: list[Event] = []
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = ",".join("?" * len(chunk))
            out += [self._event(r) for r in self.db.execute(
                f"SELECT * FROM events WHERE id IN ({q}) ORDER BY ts, id", chunk)]
        return out

    def count_events(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ---- alerts -------------------------------------------------------
    def replace_alerts(self, alerts: Iterable[Alert]) -> int:
        """Detection is a pure function of the stored events, so alerts are rebuilt each run."""
        self.db.execute("DELETE FROM alerts")
        n = 0
        for a in alerts:
            self.db.execute(
                "INSERT INTO alerts(rule,title,level,description,tags,kind,ts_first,ts_last,ts_trigger,"
                "count,grp,event_ids) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (a.rule, a.title, a.level, a.description, json.dumps(a.tags), a.kind, a.ts_first,
                 a.ts_last, a.ts_trigger, a.count, json.dumps(a.group, sort_keys=True),
                 json.dumps(a.event_ids[:MAX_EVENT_IDS_PER_ALERT])),
            )
            n += 1
        self.db.commit()
        return n

    @staticmethod
    def _alert(row: sqlite3.Row) -> Alert:
        return Alert(id=row["id"], rule=row["rule"], title=row["title"], level=row["level"],
                     description=row["description"], tags=json.loads(row["tags"]), kind=row["kind"],
                     ts_first=row["ts_first"], ts_last=row["ts_last"], ts_trigger=row["ts_trigger"],
                     count=row["count"], group=json.loads(row["grp"]),
                     event_ids=json.loads(row["event_ids"]))

    def iter_alerts(self) -> Iterator[Alert]:
        for row in self.db.execute("SELECT * FROM alerts ORDER BY ts_first, id"):
            yield self._alert(row)

    def get_alert(self, alert_id: int) -> Alert | None:
        row = self.db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert(row) if row else None
