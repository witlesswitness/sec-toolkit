"""Render scan results. Secrets are always shown redacted."""
from __future__ import annotations

import json

_MARK = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}
_LOC = {"worktree": "working tree", "history": "git history",
        "commit-msg": "commit message", "commit-meta": "commit author/committer"}


def _counts(findings):
    c = {}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def render_text(res) -> str:
    out = []
    bar = "=" * 68
    out.append(bar)
    out.append(" LEAKCHECK — secret & PII scan")
    out.append(bar)
    out.append(f" Repo    : {res.repo}")
    out.append(f" Scanned : {', '.join(res.scanned)}" + ("" if res.git else "  (not a git repo — working tree only)"))
    c = _counts(res.findings)
    summary = ", ".join(f"{c[k]} {k}" for k in ("critical", "high", "medium", "low") if k in c) or "none"
    out.append(f" Findings: {len(res.findings)}  ({summary})")
    out.append("")

    secrets = [f for f in res.findings if f.kind == "secret"]
    pii = [f for f in res.findings if f.kind == "pii"]

    def block(title, items):
        out.append(f" {title}")
        out.append(" " + "-" * 56)
        if not items:
            out.append("  none")
        for f in items:
            loc = _LOC.get(f.location, f.location)
            where = f.where + (f":{f.line_no}" if f.line_no else "")
            out.append(f"  {_MARK.get(f.severity,'[    ]')} {f.detector}")
            out.append(f"         {loc} — {where}")
            out.append(f"         value: {f.redacted}")
        out.append("")

    block("SECRETS", secrets)
    block("PII", pii)

    crit_high = [f for f in secrets if f.severity in ("critical", "high")]
    if crit_high:
        out.append(f" RESULT: {len(crit_high)} high-risk secret(s) found — rotate/remove and purge from history.")
    elif res.findings:
        out.append(" RESULT: review the findings above.")
    else:
        out.append(" RESULT: clean — no secrets or PII detected.")
    out.append("")
    out.append(" Scan repos you own or are authorized to assess. Secrets shown redacted.")
    return "\n".join(out) + "\n"


def render_json(res) -> str:
    return json.dumps({
        "repo": res.repo,
        "git": res.git,
        "scanned": res.scanned,
        "summary": _counts(res.findings),
        "findings": [
            {"severity": f.severity, "detector": f.detector, "kind": f.kind,
             "location": f.location, "where": f.where, "line": f.line_no,
             "redacted": f.redacted}
            for f in res.findings
        ],
    }, indent=2)
