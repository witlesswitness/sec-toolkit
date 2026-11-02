"""abuse.ch — URLhaus, ThreatFox, MalwareBazaar. One free Auth-Key covers all three.

- URLhaus  : malicious URL / host sightings      (url, domain, ip)
- MalwareBazaar: malware sample by hash            (md5, sha1, sha256)
- ThreatFox: IOC-to-malware/threat mapping         (any)
"""
from __future__ import annotations

from ..http import post_json
from ..models import IOCType, SourceResult
from .base import Source


class AbuseCh(Source):
    name = "abuse.ch"
    needs_key = True
    supported = {
        IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL,
        IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
    }

    def available(self) -> bool:
        return bool(self.cfg.abusech_api_key)

    def _headers(self) -> dict:
        return {"Auth-Key": self.cfg.abusech_api_key, "Accept": "application/json"}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        if not self.available():
            return SourceResult.skipped(self.name, "no ABUSECH_API_KEY")

        fields: dict[str, str] = {}

        # MalwareBazaar for hashes
        if ioc_type.is_hash:
            data, _, err = post_json(
                "https://mb-api.abuse.ch/api/v1/", self.cfg,
                data={"query": "get_info", "hash": ioc}, headers=self._headers(),
            )
            if data and data.get("query_status") == "ok":
                info = (data.get("data") or [{}])[0]
                fields["MalwareBazaar"] = (
                    f"{info.get('signature') or 'sample'} "
                    f"({info.get('file_type', '?')}, first seen {info.get('first_seen', '?')})"
                )
            elif data and data.get("query_status") == "hash_not_found":
                fields["MalwareBazaar"] = "not in MalwareBazaar"
            elif err:
                fields["MalwareBazaar"] = f"error: {err[:60]}"

        # URLhaus for url/domain/ip
        if ioc_type in (IOCType.URL, IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV6):
            endpoint = "url" if ioc_type == IOCType.URL else "host"
            key = "url" if ioc_type == IOCType.URL else "host"
            data, _, err = post_json(
                f"https://urlhaus-api.abuse.ch/v1/{endpoint}/", self.cfg,
                data={key: ioc}, headers=self._headers(),
            )
            if data and data.get("query_status") == "ok":
                if ioc_type == IOCType.URL:
                    fields["URLhaus"] = f"listed — {data.get('threat', 'malware_url')} ({data.get('url_status', '?')})"
                else:
                    count = data.get("url_count") or len(data.get("urls", []) or [])
                    fields["URLhaus"] = f"listed — {count} malicious URL(s) on host"
            elif data and data.get("query_status") in ("no_results", "not_found"):
                fields["URLhaus"] = "not listed"
            elif err:
                fields["URLhaus"] = f"error: {err[:60]}"

        # ThreatFox for everything
        data, _, err = post_json(
            "https://threatfox-api.abuse.ch/api/v1/", self.cfg,
            json_body={"query": "search_ioc", "search_term": ioc}, headers=self._headers(),
        )
        if data and data.get("query_status") == "ok" and data.get("data"):
            first = data["data"][0]
            fields["ThreatFox"] = f"{first.get('malware_printable', 'threat')} ({first.get('threat_type', '?')})"
        elif data and data.get("query_status") in ("no_result", "illegal_search_term"):
            fields["ThreatFox"] = "no match"
        elif err:
            fields["ThreatFox"] = f"error: {err[:60]}"

        if not fields:
            return SourceResult.empty(self.name, "no abuse.ch data")
        return SourceResult.ok(self.name, fields)
