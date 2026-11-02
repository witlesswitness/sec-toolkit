"""ip-api.com — free IP geolocation, ASN, ISP, and hosting/proxy flags. No key."""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source

_FIELDS = "status,message,country,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query"


class IpApi(Source):
    name = "ip-api"
    supported = {IOCType.IPV4, IOCType.IPV6}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        # Free endpoint is HTTP only.
        data, _, err = get_json(f"http://ip-api.com/json/{ioc}", self.cfg, params={"fields": _FIELDS})
        if err:
            return SourceResult.error(self.name, err)
        if not data or data.get("status") != "success":
            return SourceResult.empty(self.name, (data or {}).get("message", "no data"))

        flags = [k for k in ("proxy", "hosting", "mobile") if data.get(k)]
        return SourceResult.ok(self.name, {
            "Location": ", ".join(x for x in (data.get("city"), data.get("regionName"), data.get("country")) if x) or "-",
            "ASN": data.get("as") or data.get("asname") or "-",
            "ISP / Org": " / ".join(x for x in (data.get("isp"), data.get("org")) if x) or "-",
            "Reverse DNS": data.get("reverse") or "-",
            "Flags": ", ".join(flags) if flags else "none",
        })
