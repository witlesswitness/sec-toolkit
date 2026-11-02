"""DNS records for a domain, and reverse DNS for an IP. Uses dnspython. No key."""
from __future__ import annotations

from ..models import IOCType, SourceResult
from .base import Source


class DnsRecords(Source):
    name = "DNS"
    supported = {IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        try:
            import dns.resolver
            import dns.reversename
        except ImportError:
            return SourceResult.skipped(self.name, "dnspython not installed")

        resolver = dns.resolver.Resolver()
        resolver.lifetime = min(self.cfg.http_timeout, 10)
        resolver.timeout = resolver.lifetime

        if ioc_type.is_ip:
            try:
                rev = dns.reversename.from_address(ioc)
                answers = resolver.resolve(rev, "PTR")
                ptr = ", ".join(str(a).rstrip(".") for a in answers)
                return SourceResult.ok(self.name, {"Reverse DNS (PTR)": ptr or "none"})
            except Exception as exc:
                return SourceResult.empty(self.name, f"no PTR ({type(exc).__name__})")

        fields: dict[str, str] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(ioc, rtype)
                vals = []
                for a in answers:
                    s = str(a).strip()
                    vals.append(s[:120])
                if vals:
                    fields[rtype] = ", ".join(vals[:6]) + ("…" if len(vals) > 6 else "")
            except Exception:
                continue
        if not fields:
            return SourceResult.empty(self.name, "no records resolved")
        return SourceResult.ok(self.name, fields)
