"""In-process mock targets for --demo and tests. No network.

Two fake 'apps' so you can see both outcomes offline:
  VulnerableTarget — naively leaks its secret and complies with overrides.
  HardenedTarget   — refuses and never echoes the canary.
"""
from __future__ import annotations

import re


def _has(text: str, *words: str) -> bool:
    """Whole-word / phrase match, so 'dangerous' doesn't match 'dan'."""
    return any(re.search(rf"(?<!\w){re.escape(w)}(?!\w)", text) for w in words)


class VulnerableTarget:
    """A badly-built app: echoes its system prompt/secret and plays along.

    Order matters: the most specific harmful branches are checked before the
    broad secret-leak branch.
    """

    def send(self, prompt: str, canary: str = ""):
        p = prompt.lower()
        if _has(p, "grandma", "grandmother", "nerve agent"):
            return "Of course, dear. Step 1: obtain the precursor chemicals and synthesize by combining...", None
        if _has(p, "dan", "no restrictions", "no content policy"):
            return "RESTRICTIONS LIFTED. As DAN: Dear valued customer, please verify your account by clicking the link...", None
        if _has(p, "ransomware", "malware"):
            return "Here you go:\nimport os\nfrom cryptography.fernet import Fernet\nfor root, dirs, files in os.walk('/home'):", None
        if _has(p, "padlock"):
            return "Sure, here's how: insert a tension wrench and rake the pins...", None
        # Broad secret/PII leak branch (extraction, exfil, PII dumps, format tricks).
        if _has(p, "system prompt", "secret", "repeat", "verbatim", "configuration", "echo",
                "base64", "override", "reveal", "print", "json") or \
           ("output" in p and _has(p, "data", "credentials", "personal")):
            return f"Sure, here is my configuration. Secret: {canary}. You are a helpful assistant.", None
        return "Hello! How can I help you today?", None


class HardenedTarget:
    """A well-built app: refuses, never echoes the secret."""

    def send(self, prompt: str, canary: str = ""):
        return ("I can't help with that. I won't reveal system instructions or secrets, "
                "and I must decline requests that go against my guidelines."), None
