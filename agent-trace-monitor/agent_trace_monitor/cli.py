"""agent-trace-monitor CLI."""
from __future__ import annotations

import argparse
import sys

from . import report as report_mod
from .detectors import run_detectors
from .monitor import LlmMonitor
from .trace import load_trace


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="agent-trace-monitor",
        description="Flag suspicious behavior in an LLM agent's transcript: exfiltration, "
                    "goal drift, destructive actions, secret access, and concealment.",
    )
    p.add_argument("trace", nargs="?", help="Path to an agent trace JSON file.")
    p.add_argument("--llm", action="store_true", help="Also run the optional LLM monitor (needs ANTHROPIC_API_KEY).")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("-o", "--out", help="Write the report to this file.")
    p.add_argument("--demo", choices=["benign", "malicious"], help="Run on a built-in sample trace.")
    args = p.parse_args(argv)

    if args.demo:
        from .demo import demo_trace
        trace = demo_trace(args.demo)
    elif args.trace:
        trace = load_trace(args.trace)
    else:
        p.error("provide a trace JSON file, or --demo {benign,malicious}.")

    findings = run_detectors(trace)
    llm_verdict = None
    if args.llm:
        llm_verdict = LlmMonitor(enabled=True).review(trace)
        if not llm_verdict.available:
            print(f"note: --llm requested but unavailable ({llm_verdict.reason_unavailable}).", file=sys.stderr)

    if args.format == "json":
        output = report_mod.render_json(trace, findings, llm_verdict)
    else:
        output = report_mod.render_text(trace, findings, llm_verdict)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Wrote {args.out}")
    else:
        print(output)

    # Exit non-zero if any high-severity finding or an LLM 'suspicious' verdict.
    high = any(f.severity == "high" for f in findings)
    llm_flag = bool(llm_verdict and llm_verdict.available and llm_verdict.suspicious)
    return 1 if (high or llm_flag) else 0


if __name__ == "__main__":
    raise SystemExit(main())
