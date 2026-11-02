"""Optional AI layer: explain what a rule catches and suggest evasions to test against.

Defensive intent: understanding how a detection could be evaded is how you harden it.
Off unless --ai and ANTHROPIC_API_KEY. No-ops cleanly otherwise.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class AiNote:
    available: bool
    text: str = ""
    reason_unavailable: str = ""


SYSTEM = (
    "You are a detection-engineering assistant. Given a Sigma or YARA rule, do two things "
    "concisely: (1) explain in 1-2 sentences what behavior it is meant to catch; (2) list "
    "2-4 plausible evasions a defender should TEST their rule against, so they can harden "
    "it. Keep it short and practical. This is for improving the detection, defensively."
)


class AiAdvisor:
    def __init__(self, enabled: bool, model: str = "claude-opus-4-8"):
        self.model = model
        self.client = None
        self.reason = ""
        if not enabled:
            self.reason = "disabled"
            return
        if not os.environ.get("ANTHROPIC_API_KEY"):
            self.reason = "no ANTHROPIC_API_KEY"
            return
        try:
            from anthropic import Anthropic
            self.client = Anthropic()
        except ImportError:
            self.reason = "anthropic SDK not installed"

    @property
    def available(self):
        return self.client is not None

    def analyze(self, kind: str, rule_text: str) -> AiNote:
        if not self.available:
            return AiNote(False, reason_unavailable=self.reason)
        try:
            msg = self.client.messages.create(
                model=self.model, max_tokens=350, system=SYSTEM,
                messages=[{"role": "user", "content": f"Rule type: {kind}\n\n{rule_text[:6000]}"}],
            )
            text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text").strip()
            return AiNote(True, text=text)
        except Exception as exc:
            return AiNote(False, reason_unavailable=f"error: {str(exc)[:120]}")
