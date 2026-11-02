"""Shodan InternetDB — open ports, software (CPEs), tags, and known CVEs. No key.

https://internetdb.shodan.io/{ip}  ->  {ip, ports, cpes, hostnames, tags, vulns}
404 means Shodan has no record of the host.
"""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source


class ShodanInternetDB(Source):
    name = "Shodan InternetDB"
    supported = {IOCType.IPV4, IOCType.IPV6}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        data, status, err = get_json(f"https://internetdb.shodan.io/{ioc}", self.cfg)
        if status == 404:
            return SourceResult.empty(self.name, "host not in Shodan")
        if err:
            return SourceResult.error(self.name, err)
        if not data:
            return SourceResult.empty(self.name)

        ports = data.get("ports") or []
        vulns = data.get("vulns") or []
        tags = data.get("tags") or []
        hostnames = data.get("hostnames") or []
        fields = {
            "Open ports": ", ".join(str(p) for p in ports) if ports else "none",
            "Tags": ", ".join(tags) if tags else "none",
            "Hostnames": ", ".join(hostnames[:5]) if hostnames else "none",
            "Known CVEs": f"{len(vulns)}: " + ", ".join(vulns[:8]) + ("…" if len(vulns) > 8 else "")
            if vulns else "none",
        }
        return SourceResult.ok(self.name, fields)
