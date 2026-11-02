"""logtriage CLI."""
from __future__ import annotations

import argparse
import sys

from . import report as report_mod
from .triage import triage


def _read(args) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="logtriage",
        description="Parse logs, extract indicators, flag notable events, and build a timeline.",
    )
    p.add_argument("file", nargs="?", help="Log file to analyze (or pipe logs on stdin).")
    p.add_argument("--external-only", action="store_true", help="Ignore private/loopback IPs.")
    p.add_argument("--format", choices=["text", "json", "iocs"], default="text",
                   help="'iocs' prints a plain indicator list to pipe into ioc-enrich.")
    p.add_argument("-o", "--out", help="Write output to this file.")
    p.add_argument("--demo", action="store_true", help="Run on a built-in sample log (no files needed).")
    args = p.parse_args(argv)

    if args.demo:
        from .demo import DEMO_LOG
        text = DEMO_LOG
    else:
        text = _read(args)
        if not text.strip():
            p.error("no input. Pass a log file, pipe logs on stdin, or use --demo.")

    res = triage(text, external_only=args.external_only)
    if args.format == "json":
        output = report_mod.render_json(res)
    elif args.format == "iocs":
        output = report_mod.render_iocs(res, external_only=True)
    else:
        output = report_mod.render_text(res)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
