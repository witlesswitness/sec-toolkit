"""Correlate parsed log lines: extract indicators, tally them, flag notable events,
and build a timeline.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .extract import extract
from .parse import LogLine, parse_lines

# Lines worth surfacing on the timeline even without an IOC.
_EVENT_PATTERNS = [
    ("auth-failure", r"\b(failed password|authentication failure|invalid user|access denied|login failed)\b"),
    ("auth-success", r"\b(accepted password|session opened|login successful|authentication succeeded)\b"),
    ("privilege", r"\b(sudo|COMMAND=|su(do)? session|elevated|root)\b"),
    ("new-account", r"\b(new user|useradd|adduser|account created)\b"),
    ("error", r"\b(error|exception|fatal|panic|denied|forbidden|unauthorized|malware|quarantine)\b"),
    ("network", r"\b(connection|connect from|outbound|download|upload|transfer)\b"),
]


@dataclass
class IndicatorStat:
    value: str
    kind: str
    count: int
    scope: str = ""          # for IPs: internal / external
    first_line: int = 0
    last_line: int = 0


@dataclass
class TimelineEvent:
    lineno: int
    when: str
    tags: list[str]
    message: str


@dataclass
class TriageResult:
    total_lines: int
    parsed_with_time: int
    indicators: list[IndicatorStat]
    events: list[TimelineEvent]
    failed_auth_by_ip: list[tuple]


def _tag_line(msg: str) -> list[str]:
    tags = []
    for name, pat in _EVENT_PATTERNS:
        if re.search(pat, msg, re.IGNORECASE):
            tags.append(name)
    return tags


def triage(text: str, *, external_only: bool = False, max_events: int = 60) -> TriageResult:
    lines = parse_lines(text)
    stats: dict[tuple, IndicatorStat] = {}
    events: list[TimelineEvent] = []
    failed_auth = defaultdict(int)

    for ln in lines:
        iocs = extract(ln.message + " " + ln.raw)
        line_has_external_ip = False

        def bump(value, kind, scope=""):
            key = (kind, value)
            st = stats.get(key)
            if st is None:
                stats[key] = IndicatorStat(value, kind, 1, scope, ln.lineno, ln.lineno)
            else:
                st.count += 1
                st.last_line = ln.lineno

        for tok, scope in iocs["ipv4"]:
            if external_only and scope != "external":
                continue
            if scope == "external":
                line_has_external_ip = True
            bump(tok, "ipv4", scope)
        for kind in ("url", "domain", "md5", "sha1", "sha256", "email"):
            for v in iocs[kind]:
                bump(v, kind)

        tags = _tag_line(ln.message)
        if "auth-failure" in tags:
            for tok, scope in iocs["ipv4"]:
                failed_auth[tok] += 1

        if tags or line_has_external_ip:
            events.append(TimelineEvent(
                ln.lineno,
                ln.dt.strftime("%Y-%m-%d %H:%M:%SZ") if ln.dt else "-",
                tags or (["network"] if line_has_external_ip else []),
                ln.message[:160],
            ))

    indicators = sorted(stats.values(), key=lambda s: (-s.count, s.kind, s.value))
    events_sorted = sorted(events, key=lambda e: e.lineno)[:max_events]
    fa = sorted(failed_auth.items(), key=lambda kv: -kv[1])

    return TriageResult(
        total_lines=len(lines),
        parsed_with_time=sum(1 for l in lines if l.dt),
        indicators=indicators,
        events=events_sorted,
        failed_auth_by_ip=fa,
    )
