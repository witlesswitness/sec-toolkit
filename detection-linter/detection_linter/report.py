"""Render lint reports."""
from __future__ import annotations

import json

_MARK = {"error": "[ERROR]", "warning": "[WARN ]", "info": "[ ok  ]"}


def render_text(reports, ai_notes=None) -> str:
    ai_notes = ai_notes or {}
    out = []
    bar = "=" * 64
    out.append(bar)
    out.append(" DETECTION-LINTER")
    out.append(bar)
    n_err = sum(len(r.errors) for r in reports)
    n_warn = sum(len(r.warnings) for r in reports)
    out.append(f" Rules checked: {len(reports)}   Errors: {n_err}   Warnings: {n_warn}")
    out.append("")

    for r in reports:
        out.append(f" {r.kind.upper()}  {r.name}")
        out.append(f" {r.path}")
        out.append(" " + "-" * 56)
        for i in r.issues:
            out.append(f"  {_MARK.get(i.severity,'[     ]')} {i.code}: {i.message}")
            if i.hint:
                out.append(f"          → {i.hint}")
        note = ai_notes.get(r.path)
        if note is not None:
            out.append("")
            if note.available:
                out.append("  AI analysis:")
                for line in note.text.splitlines():
                    out.append(f"    {line}")
            else:
                out.append(f"  AI analysis: unavailable ({note.reason_unavailable})")
        out.append("")

    out.append(f" RESULT: {'issues found — see ERROR/WARN above' if (n_err or n_warn) else 'all clean'}")
    return "\n".join(out) + "\n"


def render_json(reports, ai_notes=None) -> str:
    ai_notes = ai_notes or {}
    return json.dumps([
        {
            "path": r.path, "kind": r.kind, "name": r.name, "parsed_ok": r.parsed_ok,
            "issues": [{"severity": i.severity, "code": i.code, "message": i.message, "hint": i.hint}
                       for i in r.issues],
            "ai": (ai_notes[r.path].text if (r.path in ai_notes and ai_notes[r.path].available) else None),
        }
        for r in reports
    ], indent=2)
