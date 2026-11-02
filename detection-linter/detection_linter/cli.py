"""detection-linter CLI."""
from __future__ import annotations

import argparse
import glob
import os
import sys

from . import report as report_mod
from .model import RuleReport
from .sigma import lint_sigma
from .yara import lint_yara


def _detect_kind(path: str, text: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".yml", ".yaml"):
        return "sigma"
    if ext in (".yar", ".yara"):
        return "yara"
    # content sniff
    if "detection:" in text and "logsource" in text:
        return "sigma"
    if "rule " in text and "condition:" in text:
        return "yara"
    return "unknown"


def lint_path(path: str) -> RuleReport:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    kind = _detect_kind(path, text)
    if kind == "sigma":
        return lint_sigma(path, text)
    if kind == "yara":
        return lint_yara(path, text)
    rep = RuleReport(path=path, kind="unknown", name="(unknown)", parsed_ok=False)
    from .model import Issue
    rep.issues.append(Issue("error", "unknown-type", "Could not tell if this is a Sigma or YARA rule."))
    return rep


def _expand(paths) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for ext in ("*.yml", "*.yaml", "*.yar", "*.yara"):
                out += glob.glob(os.path.join(p, "**", ext), recursive=True)
        elif any(ch in p for ch in "*?["):
            out += glob.glob(p, recursive=True)
        else:
            out.append(p)
    return sorted(set(out))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="detection-linter",
        description="Lint Sigma (.yml) and YARA (.yar) detection rules for common mistakes.",
    )
    p.add_argument("paths", nargs="*", help="Rule files, globs, or directories.")
    p.add_argument("--ai", action="store_true", help="Add AI explain/evasion analysis (needs ANTHROPIC_API_KEY).")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("-o", "--out", help="Write output to this file.")
    p.add_argument("--demo", action="store_true", help="Lint built-in sample rules (good and bad).")
    args = p.parse_args(argv)

    if args.demo:
        from .demo import write_samples
        files = write_samples()
    else:
        files = _expand(args.paths)
        if not files:
            p.error("no rule files given. Pass files/dirs/globs, or use --demo.")

    reports = [lint_path(f) for f in files]

    ai_notes = None
    if args.ai:
        from .ai import AiAdvisor
        advisor = AiAdvisor(enabled=True)
        if not advisor.available:
            print(f"note: --ai requested but unavailable ({advisor.reason}).", file=sys.stderr)
        ai_notes = {}
        for f, r in zip(files, reports):
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                ai_notes[f] = advisor.analyze(r.kind, fh.read())

    if args.format == "json":
        output = report_mod.render_json(reports, ai_notes)
    else:
        output = report_mod.render_text(reports, ai_notes)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)

    # Non-zero exit if any rule has an error-level issue.
    return 1 if any(r.errors for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
