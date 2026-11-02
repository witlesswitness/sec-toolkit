"""CIRCL hashlookup — is a file hash a KNOWN file (e.g. in NSRL)? No key.

https://hashlookup.circl.lu/lookup/{md5|sha1|sha256}/{hash}
A 200 means the hash is in at least one reference database (often a clean/known
system file); 404 means unknown. Note: this is a known-file service, not a verdict
of malicious vs. benign — treat a hit as "recognized file", a miss as "not catalogued".
"""
from __future__ import annotations

from ..http import get_json
from ..models import IOCType, SourceResult
from .base import Source

_PATH = {IOCType.MD5: "md5", IOCType.SHA1: "sha1", IOCType.SHA256: "sha256"}


class CirclHashlookup(Source):
    name = "CIRCL hashlookup"
    supported = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        kind = _PATH.get(ioc_type)
        if not kind:
            return SourceResult.skipped(self.name, "unsupported hash type")
        data, status, err = get_json(f"https://hashlookup.circl.lu/lookup/{kind}/{ioc}", self.cfg)
        if status == 404:
            return SourceResult.ok(self.name, {"Known file": "no — not in reference DBs"})
        if err or not data:
            return SourceResult.error(self.name, err or "no data")

        source_db = data.get("source") or data.get("hashlookup:source") or "reference DB"
        return SourceResult.ok(self.name, {
            "Known file": "YES — catalogued (often legitimate)",
            "File name": data.get("FileName") or data.get("filename") or "-",
            "Product": _product(data),
            "Source": source_db,
        })


def _product(data: dict) -> str:
    p = data.get("ProductName") or data.get("product")
    if isinstance(p, dict):
        return p.get("ProductName") or p.get("Name") or "-"
    return p or "-"
