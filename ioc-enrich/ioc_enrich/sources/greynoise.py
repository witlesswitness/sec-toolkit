"""GreyNoise Community API — is this IP internet background noise / a known scanner?

https://api.greynoise.io/v3/community/{ip}
Unauthenticated access is allowed at ~100 lookups/day; an optional key raises that.
"""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source


class GreyNoiseCommunity(Source):
    name = "GreyNoise"
    supported = {IOCType.IPV4, IOCType.IPV6}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        headers = {}
        if self.cfg.greynoise_api_key:
            headers["key"] = self.cfg.greynoise_api_key
        data, status, err = get_json(
            f"https://api.greynoise.io/v3/community/{ioc}", self.cfg, headers=headers or None
        )
        if status == 404:
            # 404 here means "not observed" — still a useful, valid answer.
            return SourceResult.ok(self.name, {"Classification": "not seen by GreyNoise"})
        if status == 429:
            return SourceResult.skipped(self.name, "rate limited (100/day unauthenticated)")
        if err or not data:
            return SourceResult.error(self.name, err or "no data")

        return SourceResult.ok(self.name, {
            "Classification": data.get("classification") or "unknown",
            "Noise": "yes" if data.get("noise") else "no",
            "RIOT (common business svc)": "yes" if data.get("riot") else "no",
            "Actor / name": data.get("name") or "-",
            "Last seen": data.get("last_seen") or "-",
        })
