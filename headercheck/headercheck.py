#!/usr/bin/env python3
"""headercheck — analyze raw email headers for spoofing and authentication tells.

Paste raw headers on stdin, pass a file, or point it at an .eml. Everything runs
locally: no network, no API keys. Standard library only.

    headercheck.py message.eml
    pbpaste | headercheck.py            # macOS: paste headers from clipboard
    headercheck.py --file headers.txt

What it reports:
  * SPF / DKIM / DMARC results (parsed from Authentication-Results / Received-SPF)
  * From vs Reply-To vs Return-Path domain mismatches (a classic spoof tell)
  * display-name spoofing (a brand or address in the display name that isn't the
    sending domain)
  * lookalike / homoglyph / punycode sender domains
  * the Received-hop timeline with per-hop delays

This is a triage aid, not a verdict. Headers can be forged; treat findings as
signals to weigh, not proof.
"""
from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import ipaddress
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Commonly impersonated brands and their legitimate registrable domains.
# Extend these for your own environment.
# --------------------------------------------------------------------------- #
COMMON_TARGETS = [
    "microsoft", "office365", "outlook", "apple", "icloud", "google", "gmail",
    "amazon", "paypal", "netflix", "facebook", "instagram", "linkedin",
    "docusign", "dropbox", "adobe", "chase", "wellsfargo", "bankofamerica",
    "citibank", "coinbase", "fedex", "ups", "dhl", "usps", "irs",
]
LEGIT_DOMAINS = {
    "microsoft.com", "office.com", "office365.com", "outlook.com", "live.com",
    "apple.com", "icloud.com", "google.com", "gmail.com", "amazon.com",
    "paypal.com", "netflix.com", "facebook.com", "instagram.com", "linkedin.com",
    "docusign.com", "docusign.net", "dropbox.com", "adobe.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "citibank.com", "coinbase.com",
    "fedex.com", "ups.com", "dhl.com", "usps.com", "irs.gov",
}
_CONFUSABLES = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "rn": "m", "vv": "w"}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return addr.strip().lower().rstrip(".")


def registrable(domain: str) -> str:
    """Last two labels. Good enough without a Public Suffix List dependency."""
    if not domain:
        return ""
    parts = domain.split(".")
    return ".".join(parts[-2:]).lower() if len(parts) >= 2 else domain.lower()


def _normalize_confusables(label: str) -> str:
    s = unicodedata.normalize("NFKD", label).encode("ascii", "ignore").decode("ascii").lower()
    for bad, good in _CONFUSABLES.items():
        s = s.replace(bad, good)
    return s


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_targets(full_domain: str) -> list[str]:
    reg = registrable(full_domain)
    if not reg or reg in LEGIT_DOMAINS:
        return []
    hits: list[str] = []
    tokens = re.split(r"[.\-_]", full_domain.lower())
    norm_tokens = {(_normalize_confusables(t), t) for t in tokens if t}
    for brand in COMMON_TARGETS:
        for norm, raw in norm_tokens:
            if not norm:
                continue
            if norm == brand and raw != brand:
                hits.append(brand); break
            if norm == brand and reg not in LEGIT_DOMAINS:
                hits.append(brand); break
            if len(brand) >= 5 and len(norm) == len(brand) and _levenshtein(norm, brand) == 1:
                hits.append(brand); break
            if len(brand) >= 5 and brand in norm and norm != brand:
                hits.append(brand); break
    return sorted(set(hits))


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    level: str  # "alert" | "warn" | "info" | "ok"
    text: str


@dataclass
class HeaderReport:
    from_display: str = ""
    from_addr: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    spf: str = "not found"
    dkim: str = "not found"
    dmarc: str = "not found"
    hops: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def load_message(text: str):
    return email.message_from_string(text, policy=email.policy.default)


def read_input(args) -> str:
    if args.path:
        with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def parse_auth(msg) -> tuple[str, str, str]:
    blob = " ".join(msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", [])).lower()

    def grab(mech: str) -> str:
        m = re.search(rf"\b{mech}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)", blob)
        return m.group(1) if m else "not found"

    return grab("spf"), grab("dkim"), grab("dmarc")


_RECV_IP = re.compile(r"[\[(]?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})[\])]?")


def parse_hops(msg) -> list[dict]:
    """Received headers are listed newest-first; present them oldest-first with delays."""
    received = msg.get_all("Received", []) or []
    hops = []
    for raw in received:
        raw = " ".join(raw.split())
        frm = re.search(r"\bfrom\s+([^\s;]+)", raw)
        by = re.search(r"\bby\s+([^\s;]+)", raw)
        dt = None
        if ";" in raw:
            date_part = raw.rsplit(";", 1)[1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(date_part)
            except (TypeError, ValueError):
                dt = None
        ip = None
        m = _RECV_IP.search(raw)
        if m:
            try:
                ipaddress.ip_address(m.group(1))
                ip = m.group(1)
            except ValueError:
                ip = None
        hops.append({"from": frm.group(1) if frm else "-", "by": by.group(1) if by else "-",
                     "ip": ip or "-", "dt": dt})
    hops.reverse()  # oldest first
    # compute per-hop delay
    prev = None
    for h in hops:
        if h["dt"] and prev:
            h["delay"] = int((h["dt"] - prev).total_seconds())
        else:
            h["delay"] = None
        if h["dt"]:
            prev = h["dt"]
    return hops


def analyze(text: str) -> HeaderReport:
    msg = load_message(text)
    rep = HeaderReport()

    rep.from_display, rep.from_addr = email.utils.parseaddr(msg.get("From", ""))
    rep.reply_to = [a for _, a in email.utils.getaddresses(msg.get_all("Reply-To", [])) if a]
    rep.return_path = email.utils.parseaddr(msg.get("Return-Path", ""))[1]
    rep.to = msg.get("To", "")
    rep.subject = msg.get("Subject", "")
    rep.date = msg.get("Date", "")
    rep.message_id = msg.get("Message-ID", "")
    rep.spf, rep.dkim, rep.dmarc = parse_auth(msg)
    rep.hops = parse_hops(msg)

    from_reg = registrable(domain_of(rep.from_addr))

    # Auth findings
    for mech, val in (("SPF", rep.spf), ("DKIM", rep.dkim), ("DMARC", rep.dmarc)):
        if val == "fail":
            rep.findings.append(Finding("alert", f"{mech} failed."))
        elif val == "softfail":
            rep.findings.append(Finding("warn", f"{mech} softfail."))
        elif val in ("none", "not found"):
            rep.findings.append(Finding("info", f"{mech} {val}."))
        elif val == "pass":
            rep.findings.append(Finding("ok", f"{mech} passed."))

    # Reply-To mismatch
    reply_regs = {registrable(domain_of(r)) for r in rep.reply_to if r}
    if reply_regs and from_reg and from_reg not in reply_regs:
        rep.findings.append(Finding("warn", f"Reply-To domain {sorted(reply_regs)} differs from From domain ({from_reg})."))

    # Return-Path mismatch
    rp_reg = registrable(domain_of(rep.return_path)) if rep.return_path else ""
    if rp_reg and from_reg and rp_reg != from_reg:
        rep.findings.append(Finding("warn", f"Return-Path domain ({rp_reg}) differs from From domain ({from_reg})."))

    # Display-name spoof
    disp = (rep.from_display or "").lower()
    if disp:
        embedded = re.search(r"[\w.+-]+@[\w.-]+\.\w+", disp)
        if embedded and registrable(domain_of(embedded.group(0))) != from_reg:
            rep.findings.append(Finding("alert", "Display name contains a different email address than the actual sender."))
        else:
            for brand in COMMON_TARGETS:
                if brand in disp and brand not in from_reg:
                    rep.findings.append(Finding("warn", f"Display name references '{brand}' but the sending domain is {from_reg or '(none)'}."))
                    break

    # Lookalike / punycode
    from_dom = domain_of(rep.from_addr)
    if "xn--" in from_dom:
        rep.findings.append(Finding("alert", "From domain uses punycode (xn--) — possible homoglyph spoof."))
    for brand in lookalike_targets(from_dom):
        rep.findings.append(Finding("alert", f"From domain resembles '{brand}' without being its real domain."))

    if not any(f.level in ("alert", "warn") for f in rep.findings):
        rep.findings.append(Finding("ok", "No sender-spoofing or auth-failure signals found in the headers."))

    return rep


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
_MARK = {"alert": "[!]", "warn": "[~]", "info": "[i]", "ok": "[+]"}


def render(rep: HeaderReport) -> str:
    out: list[str] = []
    bar = "=" * 64
    out.append(bar)
    out.append(" EMAIL HEADER ANALYSIS")
    out.append(bar)

    def kv(label, value):
        out.append(f" {label:<14}{value or '-'}")

    kv("From", f"{rep.from_display}  <{rep.from_addr}>" if rep.from_display else rep.from_addr)
    kv("Reply-To", ", ".join(rep.reply_to))
    kv("Return-Path", rep.return_path)
    kv("To", rep.to)
    kv("Subject", rep.subject)
    kv("Date", rep.date)
    kv("Message-ID", rep.message_id)

    out.append("")
    out.append(" AUTHENTICATION")
    out.append(" " + "-" * 40)
    out.append(f" {'SPF':<8}{rep.spf}")
    out.append(f" {'DKIM':<8}{rep.dkim}")
    out.append(f" {'DMARC':<8}{rep.dmarc}")

    out.append("")
    out.append(" FINDINGS")
    out.append(" " + "-" * 40)
    order = {"alert": 0, "warn": 1, "info": 2, "ok": 3}
    for f in sorted(rep.findings, key=lambda x: order.get(x.level, 9)):
        out.append(f" {_MARK.get(f.level, '[ ]')} {f.text}")

    if rep.hops:
        out.append("")
        out.append(" RECEIVED HOPS  (oldest first)")
        out.append(" " + "-" * 40)
        for i, h in enumerate(rep.hops, 1):
            delay = f"+{h['delay']}s" if h.get("delay") is not None else "-"
            when = h["dt"].astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ") if h.get("dt") else "-"
            out.append(f" {i:>2}. from {h['from']}  by {h['by']}")
            out.append(f"     ip {h['ip']}   {when}   delay {delay}")

    out.append("")
    out.append(" Note: headers can be forged. Treat these as signals, not proof.")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="headercheck",
        description="Analyze raw email headers for spoofing and authentication tells. Local-only, no keys.",
    )
    p.add_argument("path", nargs="?", help="An .eml file, or a text file of raw headers.")
    p.add_argument("-f", "--file", help="Read raw headers from this file.")
    args = p.parse_args(argv)

    text = read_input(args)
    if not text.strip():
        p.error("no input. Pass an .eml/headers file, or pipe headers on stdin. See --help.")

    print(render(analyze(text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
