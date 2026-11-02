"""AlienVault OTX — threat-intel pulses referencing an indicator. Free key."""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source

_SECTION = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}


class OTX(Source):
    name = "AlienVault OTX"
    needs_key = True
    supported = set(_SECTION.keys())

    def available(self) -> bool:
        return bool(self.cfg.otx_api_key)

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        if not self.available():
            return SourceResult.skipped(self.name, "no OTX_API_KEY")
        section = _SECTION[ioc_type]
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ioc}/general"
        headers = {"X-OTX-API-KEY": self.cfg.otx_api_key}
        data, status, err = get_json(url, self.cfg, headers=headers)
        if status in (401, 403):
            return SourceResult.error(self.name, "auth failed (check key)")
        if status == 404 or (data is None and not err):
            return SourceResult.empty(self.name, "no OTX record")
        if err or not data:
            return SourceResult.error(self.name, err or "no data")
        pulses = data.get("pulse_info", {}) or {}
        count = pulses.get("count", 0)
        names = [p.get("name", "") for p in pulses.get("pulses", [])[:3]]
        return SourceResult.ok(self.name, {
            "Pulses": str(count),
            "Recent pulses": "; ".join(n for n in names if n) if names else "-",
        })
