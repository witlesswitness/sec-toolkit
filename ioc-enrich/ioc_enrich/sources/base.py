"""Base class for OSINT sources."""
from __future__ import annotations

from ..models import Config, IOCType, SourceResult


class Source:
    #: Human-readable name shown in the report.
    name: str = "source"
    #: Which IOC types this source can enrich.
    supported: set[IOCType] = set()
    #: True if this source needs an API key that may be absent.
    needs_key: bool = False

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported

    def available(self) -> bool:
        """Whether this source can run (key present, if required)."""
        return True

    def query(self, ioc: str, ioc_type: IOCType) -> SourceResult:  # pragma: no cover
        raise NotImplementedError
