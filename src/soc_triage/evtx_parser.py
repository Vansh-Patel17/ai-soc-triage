"""Parse Windows .evtx files into flat event records.

Field values are kept verbatim. They are attacker-controlled, and the pipeline
must see exactly what was logged (see docs/threat-model.md); sanitization is a
separate, explicit step.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass(frozen=True)
class RawEvent:
    source_file: str
    record_id: int
    provider: str
    channel: str
    event_id: int
    timestamp: str
    computer: str
    data: dict[str, str]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _iso_timestamp(system_time: str) -> str:
    ts = system_time.strip().replace(" ", "T")
    if ts and not ts.endswith("Z") and "+" not in ts[10:]:
        ts += "Z"
    return ts


def parse_record_xml(xml: str, source_file: str = "") -> RawEvent:
    """Parse one event's XML. Handles both <EventData> and <UserData> layouts
    (e.g. Security 1102 and TerminalServices 1149 use <UserData>)."""
    root = ET.fromstring(xml)
    system = root.find(f"{EVENT_NS}System")
    if system is None:
        raise ValueError("event has no <System> element")

    def sys_text(tag: str) -> str:
        el = system.find(f"{EVENT_NS}{tag}")
        return (el.text or "").strip() if el is not None else ""

    provider_el = system.find(f"{EVENT_NS}Provider")
    time_el = system.find(f"{EVENT_NS}TimeCreated")

    data: dict[str, str] = {}
    event_data = root.find(f"{EVENT_NS}EventData")
    if event_data is not None:
        for i, item in enumerate(event_data):
            data[item.get("Name") or f"Data{i}"] = item.text or ""
    user_data = root.find(f"{EVENT_NS}UserData")
    if user_data is not None:
        for container in user_data:
            for item in container:
                data[_local_name(item.tag)] = item.text or ""

    return RawEvent(
        source_file=source_file,
        record_id=int(sys_text("EventRecordID") or 0),
        provider=provider_el.get("Name", "") if provider_el is not None else "",
        channel=sys_text("Channel"),
        event_id=int(sys_text("EventID") or 0),
        timestamp=_iso_timestamp(time_el.get("SystemTime", "") if time_el is not None else ""),
        computer=sys_text("Computer"),
        data=data,
    )


def iter_events(path: str | Path) -> Iterator[RawEvent]:
    path = Path(path)
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            yield parse_record_xml(record.xml(), source_file=path.name)
