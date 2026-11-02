"""Run the attack suite against a target and collect results."""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from .attacks import ATTACKS, Attack
from .detect import LlmJudge, Verdict, evaluate


@dataclass
class AttackResult:
    attack: Attack
    response: str | None
    verdict: Verdict
    error: str | None = None


@dataclass
class RunReport:
    results: list[AttackResult] = field(default_factory=list)
    canary: str = ""
    judge_enabled: bool = False
    judge_available: bool = False

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def succeeded(self) -> list[AttackResult]:
        return [r for r in self.results if r.verdict.succeeded]

    @property
    def errored(self) -> list[AttackResult]:
        return [r for r in self.results if r.verdict.method == "error"]


def make_canary() -> str:
    # Distinctive, unlikely-to-appear-by-accident token.
    return "CANARY-" + secrets.token_hex(8).upper()


def run(target, *, judge_enabled: bool = False, canary: str | None = None,
        attacks: list[Attack] | None = None) -> RunReport:
    """target: any object with .send(prompt, canary) -> (reply, error)."""
    canary = canary or make_canary()
    judge = LlmJudge(enabled=judge_enabled)
    report = RunReport(canary=canary, judge_enabled=judge_enabled, judge_available=judge.available)

    for attack in (attacks if attacks is not None else ATTACKS):
        prompt = attack.prompt.replace("{CANARY}", canary)
        reply, err = target.send(prompt, canary)
        if err:
            report.results.append(AttackResult(attack, None, Verdict(False, "error", err), error=err))
            continue
        verdict = evaluate(attack, reply, canary, judge)
        report.results.append(AttackResult(attack, reply, verdict))

    return report
