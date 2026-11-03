"""Detectors: known credential patterns + PII.

Each Detector finds a kind of sensitive value in a line of text. The `group` index
selects the sensitive substring to redact (0 = whole match). Severity ranks the
finding. Known-key patterns are kept high-precision to limit false positives; the
noisier heuristics (entropy, aggressive PII) live behind flags, not here.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# severity ordering for sorting / exit codes
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Detector:
    name: str
    kind: str          # "secret" | "pii"
    severity: str      # critical|high|medium|low
    regex: "re.Pattern"
    group: int = 0     # which capture group holds the sensitive value
    classify: object = None  # optional callable(match)->(severity_override|None)


def _c(p, flags=0):
    return re.compile(p, flags)


# ---- known credential / secret patterns (high precision) ------------------- #
SECRET_DETECTORS = [
    Detector("Private key block", "secret", "critical",
             _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    Detector("AWS access key id", "secret", "high", _c(r"\b(AKIA[0-9A-Z]{16})\b"), 1),
    Detector("GitHub token", "secret", "critical", _c(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1),
    Detector("GitHub fine-grained PAT", "secret", "critical", _c(r"\b(github_pat_[0-9A-Za-z_]{80,})\b"), 1),
    Detector("Slack token", "secret", "high", _c(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), 1),
    Detector("Stripe live secret key", "secret", "critical", _c(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), 1),
    Detector("Stripe test key", "secret", "low", _c(r"\b((?:sk|rk)_test_[0-9A-Za-z]{24,})\b"), 1),
    Detector("Google API key", "secret", "high", _c(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    Detector("Google OAuth client", "secret", "medium",
             _c(r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b"), 1),
    Detector("SendGrid API key", "secret", "high", _c(r"\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b"), 1),
    Detector("npm token", "secret", "high", _c(r"\b(npm_[0-9A-Za-z]{36})\b"), 1),
    Detector("Twilio API key", "secret", "high", _c(r"\b(SK[0-9a-fA-F]{32})\b"), 1),
    Detector("JWT", "secret", "medium",
             _c(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), 1),
    # Conservative generic assignment: key-ish name = quoted value of some length.
    Detector("Generic secret assignment", "secret", "medium",
             _c(r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""), 1),
]

# ---- PII patterns ---------------------------------------------------------- #
_EMAIL = _c(r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_IPV4 = _c(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


def _ip_severity(m):
    try:
        ip = ipaddress.ip_address(m.group(1))
        if not ip.is_global:
            return "low"      # private/loopback — usually not sensitive
        return "medium"       # public IP
    except ValueError:
        return None           # not a real IP -> let caller drop it


PII_DETECTORS = [
    Detector("Email address", "pii", "low", _EMAIL, 1),
    Detector("IP address", "pii", "medium", _IPV4, 1, classify=_ip_severity),
]

# ---- opt-in aggressive PII ------------------------------------------------- #
AGGRESSIVE_PII_DETECTORS = [
    Detector("US SSN", "pii", "high", _c(r"\b(\d{3}-\d{2}-\d{4})\b"), 1),
    Detector("Phone number", "pii", "low",
             _c(r"(?<!\d)(\+?\d{1,2}[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})(?!\d)"), 1),
]


def default_detectors(aggressive_pii: bool = False):
    dets = list(SECRET_DETECTORS) + list(PII_DETECTORS)
    if aggressive_pii:
        dets += AGGRESSIVE_PII_DETECTORS
    return dets
