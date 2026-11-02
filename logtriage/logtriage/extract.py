"""Self-contained indicator extraction from arbitrary text.

Finds IPv4, domains, URLs, file hashes (md5/sha1/sha256), and email addresses in a line
of log text, with defang-refang so report-pasted indicators are caught too. No deps.

Kept standalone so logtriage has no hard dependency on ioc-enrich; the extracted
indicators can be fed into ioc-enrich separately for OSINT lookups (see README).
"""
from __future__ import annotations

import ipaddress
import re

_PRIVATE_NOISE = True  # tag private/loopback IPs so they can be filtered from "external"

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE)
_HASH = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")

# Common file extensions we don't want mistaken for domains (foo.exe, bar.dll).
_FILE_EXT = {"exe", "dll", "sys", "bat", "ps1", "sh", "py", "js", "php", "jar", "bin",
             "txt", "log", "csv", "json", "xml", "html", "png", "jpg", "gif", "zip",
             "gz", "tar", "pdf", "doc", "docx", "xls", "xlsx", "conf", "cfg", "ini"}


def refang(text: str) -> str:
    s = re.sub(r"h[xX]{2}p", "http", text, flags=re.IGNORECASE)
    for bad, good in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":")):
        s = s.replace(bad, good)
    return s


def _is_ipv4(tok: str) -> bool:
    try:
        ipaddress.ip_address(tok)
        return True
    except ValueError:
        return False


def _ip_scope(tok: str) -> str:
    """external = globally routable public IP; internal = RFC1918/loopback/link-local.

    Uses is_global so genuinely public IPs are flagged external. Documentation ranges
    (TEST-NET) report is_private=True in current Python and so count as internal —
    fine, since those never appear in real traffic; real attacker IPs are global.
    """
    try:
        ip = ipaddress.ip_address(tok)
        return "external" if ip.is_global else "internal"
    except ValueError:
        return "external"


def extract(line: str) -> dict[str, list]:
    """Return {type: [values]} for one line. IPs carry a scope tag."""
    s = refang(line)
    found = {"ipv4": [], "url": [], "domain": [], "md5": [], "sha1": [], "sha256": [], "email": []}

    for m in _URL.finditer(s):
        found["url"].append(m.group(0).rstrip(".,);"))
    for m in _EMAIL.finditer(s):
        found["email"].append(m.group(0).lower())
    for m in _IPV4.finditer(s):
        tok = m.group(0)
        if _is_ipv4(tok):
            found["ipv4"].append((tok, _ip_scope(tok)))
    for m in _HASH.finditer(s):
        h = m.group(0).lower()
        n = len(h)
        if n == 32:
            found["md5"].append(h)
        elif n == 40:
            found["sha1"].append(h)
        elif n == 64:
            found["sha256"].append(h)
    # Domains last; skip ones already inside URLs/emails and obvious filenames.
    url_blob = " ".join(found["url"]) + " " + " ".join(found["email"])
    for m in _DOMAIN.finditer(s):
        dom = m.group(0).lower().rstrip(".")
        if dom in url_blob:
            continue
        tld = dom.rsplit(".", 1)[-1]
        if tld in _FILE_EXT:
            continue
        if _is_ipv4(dom):
            continue
        found["domain"].append(dom)

    # de-dupe
    for k, v in found.items():
        seen, out = set(), []
        for item in v:
            key = item if not isinstance(item, tuple) else item
            if key not in seen:
                seen.add(key)
                out.append(item)
        found[k] = out
    return found
