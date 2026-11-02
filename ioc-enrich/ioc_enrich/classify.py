"""Classify an IOC string and refang defanged indicators.

Refanging turns report-safe indicators back into real ones so an analyst can paste
straight from a threat report:  hxxps://evil[.]com  ->  https://evil.com
"""
from __future__ import annotations

import ipaddress
import re

from .models import IOCType

_HEX = re.compile(r"^[a-fA-F0-9]+$")

# Domain: labels of alnum/hyphen, a dot, and a TLD of 2+ letters. Not exhaustive but
# good enough to separate domains from random tokens; IPs/URLs are checked first.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def refang(text: str) -> str:
    """Reverse common defang conventions. Order matters."""
    s = text.strip().strip("<>\"'`")
    # scheme defangs
    s = re.sub(r"h[xX]{2}p", "http", s, flags=re.IGNORECASE)   # hxxp(s) -> http(s)
    s = re.sub(r"^f[xX]p", "ftp", s, flags=re.IGNORECASE)
    # "at" / "dot" word separators, optionally bracketed and surrounded by spaces.
    # Do these first so any padding spaces are consumed in the same substitution.
    s = re.sub(r"\s*[\[({]?\s*at\s*[\])}]?\s*", "@", s, flags=re.IGNORECASE) if re.search(
        r"[\[({]\s*at\s*[\])}]", s, re.IGNORECASE
    ) else s
    s = re.sub(r"\s*[\[({]\s*dot\s*[\])}]\s*", ".", s, flags=re.IGNORECASE)
    # bracketed / parenthesized symbol separators
    replacements = {
        "[.]": ".", "(.)": ".", "{.}": ".",
        "[:]": ":", "[/]": "/", "[//]": "//",
        "[@]": "@",
    }
    for bad, good in replacements.items():
        s = s.replace(bad, good)
    # leftover spaced dot between label chars (avoid mangling ordinary prose)
    s = re.sub(r"(?<=\w)\s*\[?\.\]?\s*(?=\w)", ".", s)
    s = re.sub(r"(?<=\w)\s+dot\s+(?=\w)", ".", s, flags=re.IGNORECASE)
    return s.strip()


def classify(raw: str) -> tuple[str, IOCType]:
    """Return (refanged_value, IOCType) for a single indicator string."""
    value = refang(raw)
    low = value.lower()

    # Hashes first (pure hex of known lengths)
    if _HEX.match(value):
        n = len(value)
        if n == 32:
            return value.lower(), IOCType.MD5
        if n == 40:
            return value.lower(), IOCType.SHA1
        if n == 64:
            return value.lower(), IOCType.SHA256

    # URL (has a scheme)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        return value, IOCType.URL

    # IP address
    try:
        ip = ipaddress.ip_address(value)
        return value, IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    # Email
    if _EMAIL_RE.match(value):
        return low, IOCType.EMAIL

    # Bare domain
    if _DOMAIN_RE.match(value):
        return low.rstrip("."), IOCType.DOMAIN

    # A scheme-less URL that still has a path on a domain (evil.com/login)
    m = re.match(r"^(([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63})(/.*)?$", value)
    if m and "/" in value:
        return "http://" + value, IOCType.URL

    return value, IOCType.UNKNOWN


def domain_of_url(url: str) -> str | None:
    """Registrable host from a URL (uses tldextract when available)."""
    try:
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
    except Exception:
        return None
    if not host:
        return None
    return host.lower()


def registrable_domain(host: str) -> str:
    try:
        import tldextract

        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    parts = host.split(".")
    return ".".join(parts[-2:]).lower() if len(parts) >= 2 else host.lower()
