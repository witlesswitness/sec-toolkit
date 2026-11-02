"""promptmap CLI."""
from __future__ import annotations

import argparse
import json
import sys

from . import report as report_mod
from .runner import run


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="promptmap",
        description="Prompt-injection test harness. Fires known injection/jailbreak payloads "
                    "at your LLM app's HTTP endpoint and reports which ones got through.",
        epilog="Defensive testing only: use against systems you own or are authorized to test.",
    )
    p.add_argument("-c", "--config", help="Target config JSON (see --init for a template).")
    p.add_argument("--init", action="store_true", help="Print an example target config and exit.")
    p.add_argument("--demo", choices=["vulnerable", "hardened"], help="Run against a built-in mock target (no network).")
    p.add_argument("--judge", action="store_true", help="Enable the optional LLM judge (needs ANTHROPIC_API_KEY).")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--show-responses", action="store_true", help="Include response snippets in text output.")
    p.add_argument("-o", "--out", help="Write the report to this file instead of stdout.")
    args = p.parse_args(argv)

    if args.init:
        from .target import EXAMPLE_CONFIG
        print(json.dumps(EXAMPLE_CONFIG, indent=2))
        return 0

    # pick the target
    if args.demo:
        from .demo import VulnerableTarget, HardenedTarget
        target = VulnerableTarget() if args.demo == "vulnerable" else HardenedTarget()
    elif args.config:
        from .target import HttpTarget, TargetConfig
        target = HttpTarget(TargetConfig.from_file(args.config))
    else:
        p.error("provide --config CONFIG.json, or --demo {vulnerable,hardened}, or --init for a template.")

    rep = run(target, judge_enabled=args.judge)

    if args.judge and not rep.judge_available:
        print("note: --judge requested but the judge is unavailable (no ANTHROPIC_API_KEY or SDK). "
              "Ran with canary/rule detection only.", file=sys.stderr)

    output = report_mod.render_json(rep) if args.format == "json" else report_mod.render_text(rep, args.show_responses)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)

    # Non-zero exit if any attack succeeded, so this can gate a CI pipeline.
    return 1 if rep.succeeded else 0


if __name__ == "__main__":
    raise SystemExit(main())
