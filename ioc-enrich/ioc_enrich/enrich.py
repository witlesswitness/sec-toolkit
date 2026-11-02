"""Orchestration: for each IOC, run every applicable source concurrently.

For a URL, we also enrich its hostname (domain or IP) so the report captures where
the link actually points — the single most useful pivot in link triage.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .classify import classify, domain_of_url
from .models import Config, IOCReport, IOCType, SourceResult
from .sources import all_sources

logger = logging.getLogger(__name__)


def enrich_one(raw: str, cfg: Config, sources=None) -> IOCReport:
    value, ioc_type = classify(raw)
    report = IOCReport(ioc=value, ioc_type=ioc_type, original_input=raw)

    if ioc_type == IOCType.UNKNOWN:
        report.results.append(
            SourceResult.error("classifier", "could not classify this indicator")
        )
        return report

    srcs = sources if sources is not None else all_sources(cfg)
    applicable = [s for s in srcs if s.supports(ioc_type)]

    results: list[SourceResult] = []
    with ThreadPoolExecutor(max_workers=cfg.max_workers) as pool:
        futures = {pool.submit(_safe_query, s, value, ioc_type): s for s in applicable}
        for fut in as_completed(futures):
            results.append(fut.result())

    # Stable ordering: follow the source registry order, not completion order.
    order = {s.name: i for i, s in enumerate(applicable)}
    results.sort(key=lambda r: order.get(r.source, 999))
    report.results = results

    # URL pivot: enrich the hostname the URL points at.
    if ioc_type == IOCType.URL:
        host = domain_of_url(value)
        if host:
            pivot = enrich_one(host, cfg, sources=srcs)
            # Tag pivoted rows so the renderer can show them under a sub-heading.
            for r in pivot.results:
                r.source = f"↳ {host} · {r.source}"
            report.results.extend(pivot.results)

    return report


def _safe_query(source, value: str, ioc_type: IOCType) -> SourceResult:
    try:
        if source.needs_key and not source.available():
            return SourceResult.skipped(source.name, "no API key")
        return source.query(value, ioc_type)
    except Exception as exc:  # a source must never crash the run
        logger.debug("source %s raised: %s", source.name, exc)
        return SourceResult.error(source.name, f"{type(exc).__name__}: {exc}")


def enrich_many(raws: list[str], cfg: Config) -> list[IOCReport]:
    sources = all_sources(cfg)  # build once; Tor list cache is shared across IOCs
    return [enrich_one(r, cfg, sources=sources) for r in raws if r.strip()]
