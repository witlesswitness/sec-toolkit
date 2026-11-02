"""Render enrichment reports.

Primary format is plain-text aligned tables that paste cleanly into a plain-text
SOC report or ticket. JSON and CSV are also available for piping into other tools.
"""
from __future__ import annotations

import csv
import io
import json

from .models import IOCReport

_STATUS_TAG = {
    "ok": "",
    "empty": "  (nothing on record)",
    "skipped": "  (skipped)",
    "error": "  (lookup failed)",
}


def _rows_for(report: IOCReport) -> list[tuple[str, str, str]]:
    """Flatten a report into (source, field, value) rows."""
    rows: list[tuple[str, str, str]] = []
    for res in report.results:
        if res.status == "ok" and res.fields:
            first = True
            for label, value in res.fields.items():
                rows.append((res.source if first else "", label, str(value)))
                first = False
        else:
            note = res.reason or _STATUS_TAG.get(res.status, "").strip() or res.status
            rows.append((res.source, f"[{res.status}]", note))
    return rows


_VALUE_CAP = 70


def _wrap(text: str, width: int) -> list[str]:
    """Soft-wrap a value onto continuation lines at word boundaries."""
    import textwrap

    text = str(text)
    lines: list[str] = []
    for part in text.split("\n"):
        wrapped = textwrap.wrap(part, width=width, break_long_words=True, break_on_hyphens=False)
        lines.extend(wrapped or [""])
    return lines or [""]


def _aligned_table(rows: list[tuple[str, str, str]], headers=("SOURCE", "FIELD", "VALUE")) -> str:
    # Source and field columns size to content; value column is capped and wrapped.
    src_w = max([len(headers[0])] + [len(str(r[0])) for r in rows], default=len(headers[0]))
    fld_w = max([len(headers[1])] + [len(str(r[1])) for r in rows], default=len(headers[1]))
    val_w = min(_VALUE_CAP, max([len(headers[2])] + [len(str(r[2])) for r in rows], default=len(headers[2])))

    def fmt_row(src, fld, val) -> str:
        val_lines = _wrap(val, val_w)
        first = f"{str(src):<{src_w}}  {str(fld):<{fld_w}}  {val_lines[0]}"
        cont_pad = " " * (src_w + 2 + fld_w + 2)
        rest = [f"{cont_pad}{line}" for line in val_lines[1:]]
        return "\n".join([first] + rest)

    sep = f"{'-' * src_w}  {'-' * fld_w}  {'-' * val_w}"
    out = [fmt_row(*headers), sep]
    out += [fmt_row(*r) for r in rows]
    return "\n".join(out)


def render_text(reports: list[IOCReport]) -> str:
    blocks: list[str] = []
    for rep in reports:
        header = f" IOC: {rep.ioc}"
        meta = f"TYPE: {rep.ioc_type.value}"
        if rep.original_input != rep.ioc:
            meta += f"   (input: {rep.original_input})"
        bar = "=" * max(len(header) + len(meta) + 3, 60)
        title = f"{header}{' ' * max(1, len(bar) - len(header) - len(meta))}{meta}"
        table = _aligned_table(_rows_for(rep))
        blocks.append(f"{bar}\n{title}\n{bar}\n{table}")
    return "\n\n".join(blocks) + "\n"


def render_json(reports: list[IOCReport]) -> str:
    out = []
    for rep in reports:
        out.append({
            "ioc": rep.ioc,
            "type": rep.ioc_type.value,
            "input": rep.original_input,
            "sources": [
                {"source": r.source, "status": r.status, "reason": r.reason, "fields": r.fields}
                for r in rep.results
            ],
        })
    return json.dumps(out, indent=2)


def render_csv(reports: list[IOCReport]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ioc", "type", "source", "status", "field", "value"])
    for rep in reports:
        for res in rep.results:
            if res.status == "ok" and res.fields:
                for label, value in res.fields.items():
                    w.writerow([rep.ioc, rep.ioc_type.value, res.source, res.status, label, value])
            else:
                w.writerow([rep.ioc, rep.ioc_type.value, res.source, res.status, "", res.reason or ""])
    return buf.getvalue()


def render(reports: list[IOCReport], fmt: str = "text") -> str:
    return {"text": render_text, "json": render_json, "csv": render_csv}[fmt](reports)
