"""Render triage results."""
from __future__ import annotations

import json


def render_text(res, max_indicators: int = 40) -> str:
    out = []
    bar = "=" * 66
    out.append(bar)
    out.append(" LOGTRIAGE")
    out.append(bar)
    out.append(f" Lines parsed     : {res.total_lines}  ({res.parsed_with_time} with timestamps)")
    out.append(f" Unique indicators: {len(res.indicators)}")
    out.append(f" Timeline events  : {len(res.events)}")
    out.append("")

    if res.failed_auth_by_ip:
        out.append(" FAILED AUTH BY SOURCE IP")
        out.append(" " + "-" * 50)
        for ip, n in res.failed_auth_by_ip[:15]:
            flag = "  <-- possible brute force" if n >= 5 else ""
            out.append(f"  {ip:<40} {n:>4}{flag}")
        out.append("")

    out.append(" INDICATORS  (by frequency)")
    out.append(" " + "-" * 50)
    if res.indicators:
        for st in res.indicators[:max_indicators]:
            scope = f" [{st.scope}]" if st.scope else ""
            span = f"lines {st.first_line}" + (f"-{st.last_line}" if st.last_line != st.first_line else "")
            out.append(f"  {st.count:>4}x  {st.kind:<7} {st.value}{scope}   ({span})")
        if len(res.indicators) > max_indicators:
            out.append(f"  ... {len(res.indicators) - max_indicators} more")
    else:
        out.append("  none found")
    out.append("")

    out.append(" TIMELINE")
    out.append(" " + "-" * 50)
    if res.events:
        for e in res.events:
            tags = ",".join(e.tags) if e.tags else "-"
            out.append(f"  L{e.lineno:<5} {e.when:<21} [{tags}]")
            out.append(f"         {e.message}")
    else:
        out.append("  no notable events")
    out.append("")
    out.append(" Triage aid. Feed the external indicators into an OSINT tool (e.g. ioc-enrich) to enrich them.")
    return "\n".join(out) + "\n"


def render_json(res) -> str:
    return json.dumps({
        "summary": {
            "lines": res.total_lines,
            "with_timestamps": res.parsed_with_time,
            "unique_indicators": len(res.indicators),
            "events": len(res.events),
        },
        "failed_auth_by_ip": [{"ip": ip, "count": n} for ip, n in res.failed_auth_by_ip],
        "indicators": [
            {"value": s.value, "kind": s.kind, "count": s.count, "scope": s.scope,
             "first_line": s.first_line, "last_line": s.last_line}
            for s in res.indicators
        ],
        "timeline": [
            {"line": e.lineno, "when": e.when, "tags": e.tags, "message": e.message}
            for e in res.events
        ],
    }, indent=2)


def render_iocs(res, external_only: bool = True) -> str:
    """Plain list of indicators, one per line — pipe straight into ioc-enrich."""
    lines = []
    for s in res.indicators:
        if s.kind == "ipv4" and external_only and s.scope != "external":
            continue
        lines.append(s.value)
    return "\n".join(lines) + ("\n" if lines else "")
