"""Windows event log parser for *exported* events (no EVTX binary parsing).

Supported inputs
----------------
* **Winlogbeat-style JSON lines**: ``{"@timestamp": ..., "winlog": {"event_id": ...,
  "computer_name": ..., "event_data": {...}}}``
* **Flat JSON lines** (documented schema): ``{"TimeCreated": ..., "EventID": 4625,
  "Computer": ..., "EventData": {...}}``
* **Event Viewer XML export** ("Save All Events As..." -> XML): a sequence of
  ``<Event>`` elements, optionally without a root element.

Normalised fields: ``EventID`` (int), ``Channel``, ``Provider``, ``Computer`` and every
``EventData`` entry flattened to the top level. For process-creation events
(4688 / Sysmon 1) ``Image``, ``ParentImage`` and ``CommandLine`` are filled in so
Sigma ``process_creation`` rules work.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Iterator

from ..models import Event


def _to_ts(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1000 if value > 1e11 else float(value)
    text = str(value).strip()
    m = re.fullmatch(r"/Date\((\d+)\)/", text)  # PowerShell ConvertTo-Json legacy format
    if m:
        return int(m.group(1)) / 1000
    text = text.replace("Z", "+00:00")
    # fromisoformat handles up to 6 fractional digits; Windows XML has 9 (100 ns ticks).
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _finish(ts: float | None, event_id: Any, computer: str, channel: str, provider: str,
            data: dict[str, Any], raw: str) -> Event | None:
    try:
        eid = int(event_id)
    except (TypeError, ValueError):
        return None
    if ts is None:
        return None
    fields: dict[str, Any] = {k: v for k, v in data.items() if v is not None}
    fields.update(EventID=eid, Channel=channel or "", Provider=provider or "", Computer=computer or "")
    if eid == 4688:
        fields.setdefault("Image", fields.get("NewProcessName", ""))
        fields.setdefault("ParentImage", fields.get("ParentProcessName", ""))
    return Event(ts=ts, source="windows", host=computer or "windows", fields=fields, raw=raw)


def parse_json_line(line: str) -> Event | None:
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None
    raw = line.rstrip("\r\n")
    if isinstance(doc.get("winlog"), dict):
        w = doc["winlog"]
        return _finish(_to_ts(doc.get("@timestamp")), w.get("event_id"), w.get("computer_name", ""),
                       w.get("channel", ""), w.get("provider_name", ""),
                       dict(w.get("event_data") or {}), raw)
    eid = doc.get("EventID", doc.get("EventId", doc.get("Id")))
    ts = _to_ts(doc.get("TimeCreated", doc.get("SystemTime", doc.get("@timestamp"))))
    return _finish(ts, eid, doc.get("Computer", doc.get("MachineName", "")),
                   doc.get("Channel", doc.get("LogName", "")),
                   doc.get("Provider", doc.get("ProviderName", "")),
                   dict(doc.get("EventData") or {}), raw)


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_xml_event(element: ET.Element, raw: str) -> Event | None:
    system = next((c for c in element if _strip_ns(c.tag) == "System"), None)
    if system is None:
        return None
    sysd: dict[str, Any] = {}
    for child in system:
        name = _strip_ns(child.tag)
        sysd[name] = child.attrib if name == "TimeCreated" else (child.text or "")
    data: dict[str, Any] = {}
    for child in element:
        if _strip_ns(child.tag) in ("EventData", "UserData"):
            for item in child.iter():
                name = item.attrib.get("Name") or _strip_ns(item.tag)
                if item is child or (len(item) and not item.attrib.get("Name")):
                    continue
                data[name] = (item.text or "").strip()
    created = sysd.get("TimeCreated", {})
    return _finish(_to_ts(created.get("SystemTime")), sysd.get("EventID"), sysd.get("Computer", ""),
                   sysd.get("Channel", ""), (sysd.get("Provider") or {}).get("Name", "")
                   if isinstance(sysd.get("Provider"), dict) else "", data, raw)


def _provider_name(element: ET.Element) -> str:
    for c in element.iter():
        if _strip_ns(c.tag) == "Provider":
            return c.attrib.get("Name", "")
    return ""


def parse_xml_text(text: str) -> Iterator[tuple[int, str, Event | None]]:
    """Yield (index, raw, event) for each <Event> in an XML export."""
    chunks = re.findall(r"<Event[ >].*?</Event>", text, flags=re.S)
    for i, chunk in enumerate(chunks, 1):
        try:
            el = ET.fromstring(chunk)
        except ET.ParseError:
            yield i, chunk, None
            continue
        ev = parse_xml_event(el, chunk)
        if ev is not None:
            ev.fields["Provider"] = ev.fields.get("Provider") or _provider_name(el)
        yield i, chunk, ev


def parse_file(path: str, host: str = "", **_) -> Iterator[tuple[int, str, Event | None]]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("<"):
        for n, raw, ev in parse_xml_text(text):
            if ev and host:
                ev.host = host
            yield n, raw, ev
        return
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        ev = parse_json_line(line)
        if ev and host:
            ev.host = host
        yield n, line, ev
