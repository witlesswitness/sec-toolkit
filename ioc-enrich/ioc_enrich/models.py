"""Shared data structures and config."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"

    @property
    def is_ip(self) -> bool:
        return self in (IOCType.IPV4, IOCType.IPV6)

    @property
    def is_hash(self) -> bool:
        return self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)


@dataclass
class SourceResult:
    """One source's answer for one IOC.

    status is one of: 'ok' (data found), 'empty' (source reachable, nothing known),
    'skipped' (no API key / not applicable), 'error' (lookup failed).
    `fields` is an ordered dict of human label -> display value for the report table.
    """
    source: str
    status: str = "ok"
    reason: str | None = None
    fields: dict[str, str] = field(default_factory=dict)

    @classmethod
    def ok(cls, source: str, fields: dict[str, str]) -> "SourceResult":
        return cls(source=source, status="ok", fields=fields)

    @classmethod
    def empty(cls, source: str, reason: str = "nothing on record") -> "SourceResult":
        return cls(source=source, status="empty", reason=reason)

    @classmethod
    def skipped(cls, source: str, reason: str) -> "SourceResult":
        return cls(source=source, status="skipped", reason=reason)

    @classmethod
    def error(cls, source: str, reason: str) -> "SourceResult":
        return cls(source=source, status="error", reason=reason[:200])


@dataclass
class IOCReport:
    ioc: str
    ioc_type: IOCType
    original_input: str  # what the user typed, before refang
    results: list[SourceResult] = field(default_factory=list)


@dataclass
class Config:
    virustotal_api_key: str | None = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY") or None)
    abuseipdb_api_key: str | None = field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY") or None)
    abusech_api_key: str | None = field(default_factory=lambda: os.environ.get("ABUSECH_API_KEY") or None)
    otx_api_key: str | None = field(default_factory=lambda: os.environ.get("OTX_API_KEY") or None)
    greynoise_api_key: str | None = field(default_factory=lambda: os.environ.get("GREYNOISE_API_KEY") or None)

    http_timeout: int = field(default_factory=lambda: int(os.environ.get("IOC_HTTP_TIMEOUT", "12") or 12))
    max_workers: int = field(default_factory=lambda: int(os.environ.get("IOC_MAX_WORKERS", "8") or 8))
    crtsh_max_subdomains: int = field(
        default_factory=lambda: int(os.environ.get("IOC_CRTSH_MAX_SUBDOMAINS", "15") or 15)
    )

    user_agent: str = "ioc-enrich/0.1 (OSINT enrichment tool)"
