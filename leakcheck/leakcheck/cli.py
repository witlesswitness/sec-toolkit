"""leakcheck CLI."""
from __future__ import annotations

import argparse
import os
import sys

from . import report as report_mod


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="leakcheck",
        description="Scan a local git repo for leaked secrets and PII — in the working "
                    "tree, the full commit history, and commit messages/metadata.",
        epilog="Scan repos you own or are authorized to assess.",
    )
    p.add_argument("repo", nargs="?", help="Path to a local repo (or any directory).")
    p.add_argument("--no-history", action="store_true", help="Scan only the working tree, skip git history.")
    p.add_argument("--entropy", action="store_true", help="Also flag high-entropy strings (more coverage, more noise).")
    p.add_argument("--entropy-threshold", type=float, default=4.0, help="Entropy cutoff (default 4.0).")
    p.add_argument("--aggressive-pii", action="store_true", help="Also detect phone/SSN-style patterns (noisier).")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("-o", "--out", help="Write output to this file.")
    p.add_argument("--demo", action="store_true", help="Build a throwaway repo with planted FAKE secrets and scan it.")
    args = p.parse_args(argv)

    from .scan import scan_repo

    if args.demo:
        from .demo import build_demo_repo
        repo = build_demo_repo()
    else:
        if not args.repo:
            p.error("provide a path to a local repo, or use --demo.")
        if not os.path.isdir(args.repo):
            p.error(f"not a directory: {args.repo}")
        repo = args.repo

    res = scan_repo(
        repo,
        history=not args.no_history,
        aggressive_pii=args.aggressive_pii,
        entropy=args.entropy,
        entropy_threshold=args.entropy_threshold,
    )

    output = report_mod.render_json(res) if args.format == "json" else report_mod.render_text(res)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)

    # exit non-zero if any critical/high secret was found (CI gate)
    risky = any(f.kind == "secret" and f.severity in ("critical", "high") for f in res.findings)
    return 1 if risky else 0


if __name__ == "__main__":
    raise SystemExit(main())
