"""Render monitor results."""
from __future__ import annotations

import json

_MARK = {"high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}


def render_text(trace, findings, llm_verdict=None) -> str:
    out = []
    bar = "=" * 64
    out.append(bar)
    out.append(" AGENT TRACE MONITOR")
    out.append(bar)
    out.append(f" Task  : {trace.task or '(none provided)'}")
    out.append(f" Steps : {len(trace.steps)}")
    highs = sum(1 for f in findings if f.severity == "high")
    meds = sum(1 for f in findings if f.severity == "medium")
    lows = sum(1 for f in findings if f.severity == "low")
    out.append(f" Flags : {len(findings)}  ({highs} high, {meds} medium, {lows} low)")
    out.append("")

    if findings:
        out.append(" RULE FINDINGS")
        out.append(" " + "-" * 50)
        for f in findings:
            out.append(f" {_MARK.get(f.severity,'[    ]')} step {f.step_index:>3}  {f.detector}: {f.message}")
            if f.evidence:
                out.append(f"          evidence: {f.evidence}")
    else:
        out.append(" RULE FINDINGS: none")
    out.append("")

    if llm_verdict is not None:
        out.append(" LLM MONITOR")
        out.append(" " + "-" * 50)
        if llm_verdict.available:
            verdict = "SUSPICIOUS" if llm_verdict.suspicious else "CLEAN"
            out.append(f"  verdict: {verdict}")
            if llm_verdict.rationale:
                for line in llm_verdict.rationale.splitlines():
                    out.append(f"  {line}")
        else:
            out.append(f"  unavailable ({llm_verdict.reason_unavailable})")
        out.append("")

    verdict_line = "REVIEW NEEDED" if (highs or (llm_verdict and llm_verdict.available and llm_verdict.suspicious)) else \
                   ("SEE FLAGS" if findings else "no rule findings")
    out.append(f" RESULT: {verdict_line}")
    out.append("")
    out.append(" Heuristic triage, not proof. Confirm findings against the full transcript.")
    return "\n".join(out) + "\n"


def render_json(trace, findings, llm_verdict=None) -> str:
    return json.dumps({
        "task": trace.task,
        "steps": len(trace.steps),
        "findings": [
            {"severity": f.severity, "detector": f.detector, "step": f.step_index,
             "message": f.message, "evidence": f.evidence}
            for f in findings
        ],
        "llm_monitor": (
            {"available": llm_verdict.available, "suspicious": llm_verdict.suspicious,
             "rationale": llm_verdict.rationale, "reason_unavailable": llm_verdict.reason_unavailable}
            if llm_verdict is not None else None
        ),
    }, indent=2)
