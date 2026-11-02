"""Canned reports for --demo: shows the output format with no network calls.

The data here is illustrative (and uses documentation/example indicators), so the
tool can be demonstrated and the renderer tested offline.
"""
from __future__ import annotations

from .models import IOCReport, IOCType, SourceResult


def demo_reports() -> list[IOCReport]:
    ip = IOCReport(ioc="185.220.101.47", ioc_type=IOCType.IPV4, original_input="185[.]220[.]101[.]47")
    ip.results = [
        SourceResult.ok("ip-api", {
            "Location": "Frankfurt, Hesse, Germany",
            "ASN": "AS205100 F3 Netze e.V.",
            "ISP / Org": "F3 Netze / Tor exit",
            "Reverse DNS": "tor-exit-47.relay.example",
            "Flags": "hosting",
        }),
        SourceResult.ok("Shodan InternetDB", {
            "Open ports": "22, 443, 9001, 9030",
            "Tags": "tor",
            "Hostnames": "none",
            "Known CVEs": "none",
        }),
        SourceResult.ok("GreyNoise", {
            "Classification": "malicious",
            "Noise": "yes",
            "RIOT (common business svc)": "no",
            "Actor / name": "Tor scanner",
            "Last seen": "2026-10-31",
        }),
        SourceResult.ok("Tor exit list", {"Tor exit node": "YES"}),
        SourceResult.ok("DNS", {"Reverse DNS (PTR)": "tor-exit-47.relay.example"}),
        SourceResult.skipped("AbuseIPDB", "no ABUSEIPDB_API_KEY"),
        SourceResult.skipped("VirusTotal", "no VIRUSTOTAL_API_KEY"),
    ]

    dom = IOCReport(ioc="secure-login-update.com", ioc_type=IOCType.DOMAIN, original_input="secure-login-update[.]com")
    dom.results = [
        SourceResult.ok("DNS", {
            "A": "104.21.5.12, 172.67.200.9",
            "MX": "10 mail.secure-login-update.com",
            "NS": "ns1.cloudflare.com, ns2.cloudflare.com",
        }),
        SourceResult.ok("RDAP / WHOIS", {
            "Registrar": "NameSilo, LLC",
            "Created": "2026-10-20T00:00:00Z",
            "Age": "12 days",
            "Expires": "2027-10-20T00:00:00Z",
            "Status": "clientTransferProhibited",
        }),
        SourceResult.ok("crt.sh (CT logs)", {
            "Certs seen": "3",
            "Subdomains": "mail.secure-login-update.com, www.secure-login-update.com",
        }),
        SourceResult.empty("VirusTotal", "not seen by VT"),
    ]

    h = IOCReport(
        ioc="44d88612fea8a8f36de82e1278abb02f",
        ioc_type=IOCType.MD5,
        original_input="44d88612fea8a8f36de82e1278abb02f",
    )
    h.results = [
        SourceResult.ok("CIRCL hashlookup", {"Known file": "no — not in reference DBs"}),
        SourceResult.skipped("VirusTotal", "no VIRUSTOTAL_API_KEY"),
        SourceResult.skipped("abuse.ch", "no ABUSECH_API_KEY"),
    ]

    return [ip, dom, h]
