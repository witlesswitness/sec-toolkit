"""crt.sh — certificate-transparency subdomain discovery for a domain. No key."""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source


class CrtSh(Source):
    name = "crt.sh (CT logs)"
    supported = {IOCType.DOMAIN}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        # output=json returns one row per cert; name_value may hold several SANs.
        data, _, err = get_json(
            "https://crt.sh/", self.cfg, params={"q": ioc, "output": "json"}
        )
        if err:
            return SourceResult.error(self.name, err)
        if not data:
            return SourceResult.empty(self.name, "no certificates found")

        subs: set[str] = set()
        for row in data:
            for name in (row.get("name_value") or "").splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(ioc) and name != ioc:
                    subs.add(name)
        cap = self.cfg.crtsh_max_subdomains
        shown = sorted(subs)[:cap]
        more = len(subs) - len(shown)
        return SourceResult.ok(self.name, {
            "Certs seen": str(len(data)),
            "Subdomains": (", ".join(shown) + (f"  (+{more} more)" if more > 0 else "")) if shown else "none",
        })
