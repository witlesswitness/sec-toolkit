"""VirusTotal v3 — reputation for IP, domain, URL, and file hash. Free key."""
from __future__ import annotations

import base64

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(Source):
    name = "VirusTotal"
    needs_key = True
    supported = {
        IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL,
        IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
    }

    def available(self) -> bool:
        return bool(self.cfg.virustotal_api_key)

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        if not self.available():
            return SourceResult.skipped(self.name, "no VIRUSTOTAL_API_KEY")

        if ioc_type.is_ip:
            path = f"ip_addresses/{ioc}"
        elif ioc_type == IOCType.DOMAIN:
            path = f"domains/{ioc}"
        elif ioc_type == IOCType.URL:
            uid = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            path = f"urls/{uid}"
        elif ioc_type.is_hash:
            path = f"files/{ioc}"
        else:
            return SourceResult.skipped(self.name, "unsupported type")

        headers = {"x-apikey": self.cfg.virustotal_api_key}
        data, status, err = get_json(f"{_BASE}/{path}", self.cfg, headers=headers)
        if status == 404:
            return SourceResult.empty(self.name, "not seen by VT")
        if status in (401, 403):
            return SourceResult.error(self.name, "auth failed (check key)")
        if err or not data:
            return SourceResult.error(self.name, err or "no data")

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        fields = {"Detections": f"{mal} malicious / {susp} suspicious / {total} engines"}
        if attrs.get("reputation") is not None:
            fields["Reputation"] = str(attrs.get("reputation"))
        if ioc_type.is_hash:
            fields["File type"] = attrs.get("type_description") or "-"
            fields["Name"] = attrs.get("meaningful_name") or "-"
        return SourceResult.ok(self.name, fields)
