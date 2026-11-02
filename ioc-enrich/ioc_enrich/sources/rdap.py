"""RDAP registration data for a domain (registrar, creation date, age). No key.

rdap.org proxies to the authoritative RDAP server for the TLD.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source


class Rdap(Source):
    name = "RDAP / WHOIS"
    supported = {IOCType.DOMAIN}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        data, status, err = get_json(f"https://rdap.org/domain/{ioc}", self.cfg)
        if status == 404:
            return SourceResult.empty(self.name, "no RDAP record")
        if err or not data:
            return SourceResult.error(self.name, err or "no data")

        registrar = "-"
        for ent in data.get("entities", []) or []:
            roles = ent.get("roles", []) or []
            if "registrar" in roles:
                registrar = _entity_name(ent) or registrar
                break

        created = _event_date(data, "registration")
        expires = _event_date(data, "expiration")
        age_str = "-"
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - dt).days
                age_str = f"{age_days} days"
            except Exception:
                pass

        statuses = data.get("status", []) or []
        return SourceResult.ok(self.name, {
            "Registrar": registrar,
            "Created": created or "-",
            "Age": age_str,
            "Expires": expires or "-",
            "Status": ", ".join(statuses[:4]) if statuses else "-",
        })


def _entity_name(ent: dict) -> str | None:
    # RDAP names live in jCard (vcardArray). Pull the 'fn' entry if present.
    try:
        vcard = ent.get("vcardArray", [])
        if len(vcard) == 2:
            for item in vcard[1]:
                if item and item[0] == "fn":
                    return item[3]
    except Exception:
        pass
    return ent.get("handle")


def _event_date(data: dict, action: str) -> str | None:
    for ev in data.get("events", []) or []:
        if ev.get("eventAction") == action:
            return ev.get("eventDate")
    return None
