"""Enrichment: cached wrappers over OSV, PyPI, and the Hugging Face Hub."""

from __future__ import annotations

from ladex.engine.enrich.cache import Cache, cached_json
from ladex.engine.enrich.http import Fetcher, FetchResult, HttpFetcher
from ladex.engine.enrich.lockfiles import normalize, resolve_versions
from ladex.engine.enrich.models import (
    UNDOCUMENTED,
    EnrichedModel,
    EnrichedPackage,
    EnrichmentReport,
    EnrichStatus,
    ModelInfo,
    PyPIInfo,
    Vuln,
)
from ladex.engine.enrich.service import enrich_scan

__all__ = [
    "UNDOCUMENTED",
    "Cache",
    "EnrichStatus",
    "EnrichedModel",
    "EnrichedPackage",
    "EnrichmentReport",
    "FetchResult",
    "Fetcher",
    "HttpFetcher",
    "ModelInfo",
    "PyPIInfo",
    "Vuln",
    "cached_json",
    "enrich_scan",
    "normalize",
    "resolve_versions",
]
