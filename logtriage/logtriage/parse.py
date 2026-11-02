"""Log-line parsing: timestamp + message, across a few common formats.

Handles, best-effort:
  * syslog / auth.log      "Nov  1 10:00:00 host proc[pid]: message"
  * ISO-8601 prefixed       "2026-11-01T10:00:00Z message" / "2026-11-01 10:00:00 message"
  * JSON lines              {"time"/"timestamp"/"ts": ..., "message"/"msg": ...}
  * anything else           no timestamp; message = whole line

Timestamps are parsed to aware datetimes in UTC where possible (syslog has no year, so
the current year is assumed).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$")
_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass
class LogLine:
    lineno: int
    raw: str
    dt: datetime | None
    message: str


def _parse_iso(s: str) -> datetime | None:
    try:
        s2 = s.replace("Z", "+00:00").replace(" ", "T", 1) if "T" not in s else s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_syslog(s: str) -> datetime | None:
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", s)
    if not m:
        return None
    mon, day, hh, mm, ss = m.groups()
    year = datetime.now(timezone.utc).year
    try:
        return datetime(year, _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return None


def parse_line(lineno: int, raw: str) -> LogLine:
    line = raw.rstrip("\n")
    stripped = line.strip()

    # JSON line
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
            ts = obj.get("time") or obj.get("timestamp") or obj.get("ts") or obj.get("@timestamp")
            msg = obj.get("message") or obj.get("msg") or stripped
            dt = _parse_iso(str(ts)) if ts else None
            return LogLine(lineno, line, dt, msg if isinstance(msg, str) else json.dumps(msg))
        except ValueError:
            pass

    m = _ISO.match(stripped)
    if m:
        return LogLine(lineno, line, _parse_iso(m.group(1)), m.group(2))

    m = _SYSLOG.match(stripped)
    if m:
        return LogLine(lineno, line, _parse_syslog(m.group(1)), m.group(2))

    return LogLine(lineno, line, None, stripped)


def parse_lines(text: str) -> list[LogLine]:
    return [parse_line(i, raw) for i, raw in enumerate(text.splitlines(), 1) if raw.strip()]
