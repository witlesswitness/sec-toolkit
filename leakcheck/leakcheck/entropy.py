"""Optional high-entropy string detection for unknown secret shapes (--entropy)."""
from __future__ import annotations

import math
import re

# candidate tokens: long-ish base64/hex-ish runs
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_findings(line: str, threshold: float = 4.0):
    """Yield (token, entropy) for high-entropy tokens that look secret-ish."""
    for m in _TOKEN.finditer(line):
        tok = m.group(0)
        # require some mix (not a single-char repeat or plain word)
        if len(set(tok)) < 8:
            continue
        e = shannon_entropy(tok)
        if e >= threshold:
            yield tok, round(e, 2)
