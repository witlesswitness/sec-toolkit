"""OSINT source registry.

Each source is a Source subclass. `all_sources(cfg)` returns instances; the
orchestrator asks each whether it `supports(ioc_type)` and calls `query()`.
"""
from __future__ import annotations

from .base import Source
from .ip_api import IpApi
from .shodan_internetdb import ShodanInternetDB
from .greynoise import GreyNoiseCommunity
from .tor_exit import TorExit
from .dns_records import DnsRecords
from .rdap import Rdap
from .crtsh import CrtSh
from .circl_hashlookup import CirclHashlookup
from .virustotal import VirusTotal
from .abuseipdb import AbuseIPDB
from .abusech import AbuseCh
from .otx import OTX


def all_sources(cfg) -> list[Source]:
    return [
        # zero-key
        IpApi(cfg),
        ShodanInternetDB(cfg),
        GreyNoiseCommunity(cfg),
        TorExit(cfg),
        DnsRecords(cfg),
        Rdap(cfg),
        CrtSh(cfg),
        CirclHashlookup(cfg),
        # optional-key
        VirusTotal(cfg),
        AbuseIPDB(cfg),
        AbuseCh(cfg),
        OTX(cfg),
    ]
