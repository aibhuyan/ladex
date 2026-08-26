"""Enrichment orchestration: turn a ScanResult into an EnrichmentReport.

Maps detections to the things worth looking up — PyPI distributions for package-level
signals, Hugging Face repos for model-id strings — then fans out to the cached providers.
CVE lookup is chained after PyPI because OSV needs a concrete version to query.
"""

from __future__ import annotations

from pathlib import Path

from ladex.engine.enrich import hfhub, osv, pypi
from ladex.engine.enrich.cache import Cache
from ladex.engine.enrich.http import Fetcher, HttpFetcher
from ladex.engine.enrich.lockfiles import normalize, resolve_versions
from ladex.engine.enrich.models import (
    EnrichedModel,
    EnrichedPackage,
    EnrichmentReport,
    EnrichStatus,
    Vuln,
)
from ladex.engine.scan import ScanResult


def package_targets(result: ScanResult) -> set[str]:
    """PyPI distribution names implied by non-string detections."""
    names: set[str] = set()
    for det in result.detections:
        if det.match_kind == "string":
            continue
        top = det.evidence.split(".", 1)[0]
        if top:
            names.add(pypi.module_to_distribution(top))
    return names


def model_targets(result: ScanResult) -> set[str]:
    """Hugging Face repo ids implied by model-id string detections."""
    return {
        det.evidence
        for det in result.detections
        if det.component_type.value == "model" and hfhub.looks_like_repo_id(det.evidence)
    }


def enrich_scan(
    result: ScanResult,
    *,
    fetcher: Fetcher | None = None,
    cache: Cache | None = None,
    offline: bool = False,
    hf_token: str | None = None,
    root: Path | None = None,
) -> EnrichmentReport:
    fetcher = fetcher if fetcher is not None else HttpFetcher()
    cache = cache if cache is not None else Cache()
    # Pin each package to the version actually locked in the project, so CVEs are accurate.
    locked = resolve_versions(root) if root is not None else {}

    packages: dict[str, EnrichedPackage] = {}
    for name in sorted(package_targets(result)):
        info = pypi.fetch_package(name, fetcher, cache, offline=offline)
        pinned = locked.get(normalize(name))
        resolved_version = pinned[0] if pinned else None
        version_source = pinned[1] if pinned else ("pypi-latest" if info.version else None)
        effective = resolved_version or info.version

        vulns: tuple[Vuln, ...] = ()
        vulns_status = EnrichStatus.OFFLINE
        if effective:
            vulns, vulns_status = osv.fetch_vulns(name, effective, fetcher, cache, offline=offline)
        packages[name] = EnrichedPackage(
            name=name,
            pypi=info,
            vulns=vulns,
            vulns_status=vulns_status,
            resolved_version=resolved_version,
            version_source=version_source,
        )

    models: dict[str, EnrichedModel] = {}
    for repo_id in sorted(model_targets(result)):
        info_model = hfhub.fetch_model(repo_id, fetcher, cache, offline=offline, token=hf_token)
        models[repo_id] = EnrichedModel(repo_id=repo_id, hf=info_model)

    return EnrichmentReport(offline=offline, packages=packages, models=models)
