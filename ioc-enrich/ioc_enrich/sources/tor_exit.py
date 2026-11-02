"""Tor exit-node check against the official bulk exit list. No key.

The list (https://check.torproject.org/torbulkexitlist) is plain text, one IP per
line. We fetch it once and cache it for the whole run.
"""
from __future__ import annotations

from ..http import get_text
from ..models import IOCType, SourceResult
from .base import Source

_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"


class TorExit(Source):
    name = "Tor exit list"
    supported = {IOCType.IPV4, IOCType.IPV6}

    _cache: set[str] | None = None
    _cache_error: str | None = None

    def _load(self) -> set[str] | None:
        if TorExit._cache is not None:
            return TorExit._cache
        if TorExit._cache_error is not None:
            return None
        text, _, err = get_text(_EXIT_LIST_URL, self.cfg)
        if err or text is None:
            TorExit._cache_error = err or "fetch failed"
            return None
        TorExit._cache = {line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")}
        return TorExit._cache

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:
        exits = self._load()
        if exits is None:
            return SourceResult.error(self.name, TorExit._cache_error or "unavailable")
        is_exit = ioc in exits
        return SourceResult.ok(self.name, {
            "Tor exit node": "YES" if is_exit else "no",
        })
