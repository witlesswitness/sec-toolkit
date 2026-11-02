"""AbuseIPDB — crowd-sourced IP abuse reputation. Free key."""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source


class AbuseIPDB(Source):
    name = "AbuseIPDB"
    needs_key = True
    supported = {IOCType.IPV4, IOCType.IPV6}

    def available(self) -> bool:
        return bool(self.cfg.abuseipdb_api_key)

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        if not self.available():
            return SourceResult.skipped(self.name, "no ABUSEIPDB_API_KEY")
        headers = {"Key": self.cfg.abuseipdb_api_key, "Accept": "application/json"}
        data, status, err = get_json(
            "https://api.abuseipdb.com/api/v2/check", self.cfg,
            headers=headers, params={"ipAddress": ioc, "maxAgeInDays": 90},
        )
        if status in (401, 403):
            return SourceResult.error(self.name, "auth failed (check key)")
        if err or not data:
            return SourceResult.error(self.name, err or "no data")
        d = data.get("data", {})
        return SourceResult.ok(self.name, {
            "Abuse score": f"{d.get('abuseConfidenceScore', 0)}% confidence",
            "Reports": f"{d.get('totalReports', 0)} (last 90d)",
            "Usage type": d.get("usageType") or "-",
            "ISP": d.get("isp") or "-",
            "Tor": "yes" if d.get("isTor") else "no",
        })
