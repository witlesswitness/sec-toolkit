"""Command-line entrypoint for ioc-enrich."""
from __future__ import annotations

import argparse
import sys

from .models import Config
from .render import render


def _read_inputs(args) -> list[str]:
    items: list[str] = []
    items += args.iocs
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            items += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    if args.stdin or (not items and not sys.stdin.isatty()):
        items += [ln.strip() for ln in sys.stdin if ln.strip() and not ln.lstrip().startswith("#")]
    # de-dupe, keep order
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="Enrich IOCs (IP, domain, URL, hash, email) with free OSINT and print a report table.",
    )
    p.add_argument("iocs", nargs="*", help="One or more indicators. Defanged input is accepted.")
    p.add_argument("-f", "--file", help="File with one IOC per line (# comments allowed).")
    p.add_argument("--stdin", action="store_true", help="Also read IOCs from stdin.")
    p.add_argument("--format", choices=["text", "json", "csv"], default="text", help="Output format.")
    p.add_argument("-o", "--out", help="Write output to this file instead of stdout.")
    p.add_argument("--demo", action="store_true", help="Run on canned sample data (no network). Shows the output format.")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    import logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.demo:
        from .demo import demo_reports
        reports = demo_reports()
    else:
        iocs = _read_inputs(args)
        if not iocs:
            p.error("no IOCs given. Pass them as arguments, with --file, via stdin, or try --demo.")
        from .enrich import enrich_many
        reports = enrich_many(iocs, Config())

    output = render(reports, args.format)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
