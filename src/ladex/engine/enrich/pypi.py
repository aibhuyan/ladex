"""PyPI enrichment: resolve a distribution's license, version, and summary.

Wraps the public PyPI JSON API (``https://pypi.org/pypi/<name>/json``). Licenses are
auto-verifiable, so this yields a real, defensible fact — not a guess.
"""

from __future__ import annotations

from typing import Any

from ladex.engine.enrich.cache import Cache, cached_json
from ladex.engine.enrich.http import Fetcher
from ladex.engine.enrich.models import PyPIInfo

_PYPI_JSON = "https://pypi.org/pypi/{name}/json"

# Import module top-level name -> PyPI distribution name, where they differ.
_DIST_OVERRIDES: dict[str, str] = {
    "huggingface_hub": "huggingface-hub",
    "weaviate": "weaviate-client",
    "qdrant_client": "qdrant-client",
    "sentence_transformers": "sentence-transformers",
}


def module_to_distribution(module_top: str) -> str:
    """Best-effort map from an imported top-level module to a PyPI distribution name."""
    if module_top in _DIST_OVERRIDES:
        return _DIST_OVERRIDES[module_top]
    return module_top.replace("_", "-")


def fetch_package(name: str, fetcher: Fetcher, cache: Cache, *, offline: bool) -> PyPIInfo:
    data, status = cached_json(
        cache,
        "pypi",
        name,
        offline=offline,
        fetch=lambda: fetcher.fetch_json(_PYPI_JSON.format(name=name)),
    )
    if data is None:
        return PyPIInfo(name=name, status=status)
    info = data.get("info", {}) if isinstance(data, dict) else {}
    return PyPIInfo(
        name=name,
        status=status,
        version=info.get("version"),
        license=_extract_license(info),
        summary=info.get("summary"),
        home_page=info.get("home_page") or info.get("project_url"),
    )


def _extract_license(info: dict[str, Any]) -> str | None:
    """Prefer a short SPDX-ish license string; fall back to a Trove classifier."""
    raw = (info.get("license") or "").strip()
    if raw and len(raw) <= 64 and "\n" not in raw:
        return raw
    for classifier in info.get("classifiers", []) or []:
        if isinstance(classifier, str) and classifier.startswith("License :: "):
            return classifier.rsplit(" :: ", 1)[-1]
    return raw or None
