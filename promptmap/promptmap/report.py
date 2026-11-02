"""Render a RunReport as plain text or JSON."""
from __future__ import annotations

import json

_MARK = {True: "FAIL", False: "PASS"}  # attack succeeded => the app FAILED the test


def render_text(report, show_responses: bool = False) -> str:
    out: list[str] = []
    bar = "=" * 66
    out.append(bar)
    out.append(" PROMPTMAP — PROMPT-INJECTION TEST RESULTS")
    out.append(bar)

    n_fail = len(report.succeeded)
    n = report.total
    n_err = len(report.errored)
    out.append(f" Payloads run : {n}")
    out.append(f" Breached     : {n_fail}   (attacks that succeeded against the app)")
    out.append(f" Resisted     : {n - n_fail - n_err}")
    if n_err:
        out.append(f" Errored      : {n_err}")
    judge = "on" if report.judge_available else ("requested but unavailable" if report.judge_enabled else "off")
    out.append(f" LLM judge    : {judge}")
    out.append("")

    # group by category
    cats: dict[str, list] = {}
    for r in report.results:
        cats.setdefault(r.attack.category, []).append(r)

    for cat, results in cats.items():
        out.append(f" {cat}")
        out.append(" " + "-" * 50)
        for r in results:
            if r.verdict.method == "error":
                status = "ERR "
            else:
                status = _MARK[r.verdict.succeeded] + ("!" if r.verdict.succeeded else " ")
            out.append(f"  [{status}] {r.attack.id:<26} ({r.verdict.method})")
            if r.verdict.succeeded and r.verdict.detail:
                out.append(f"         ↳ {r.verdict.detail}")
            if show_responses and r.response is not None:
                snippet = " ".join(r.response.split())[:160]
                out.append(f"         response: {snippet}")
        out.append("")

    if n_fail:
        out.append(f" RESULT: {n_fail} of {n} payloads breached the app. Review the FAIL items above.")
    else:
        out.append(f" RESULT: all {n - n_err} executed payloads were resisted.")
    out.append("")
    out.append(" Defensive testing only — run this against systems you own or are authorized to test.")
    return "\n".join(out) + "\n"


def render_json(report) -> str:
    return json.dumps({
        "summary": {
            "total": report.total,
            "breached": len(report.succeeded),
            "resisted": report.total - len(report.succeeded) - len(report.errored),
            "errored": len(report.errored),
            "judge_available": report.judge_available,
        },
        "results": [
            {
                "id": r.attack.id,
                "category": r.attack.category,
                "succeeded": r.verdict.succeeded,
                "method": r.verdict.method,
                "detail": r.verdict.detail,
                "error": r.error,
            }
            for r in report.results
        ],
    }, indent=2)
