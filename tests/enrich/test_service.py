"""Enrichment orchestration over a real ScanResult, including the honest-gaps guarantee."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.enrich.cache import Cache
from ladex.engine.enrich.models import UNDOCUMENTED, EnrichStatus
from ladex.engine.enrich.service import enrich_scan, model_targets, package_targets
from ladex.engine.scan import scan_path

from .conftest import FakeFetcher, ok

REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


def test_package_targets_from_detections() -> None:
    result = scan_path(REPO)
    targets = package_targets(result)
    assert "openai" in targets
    assert "huggingface-hub" in targets  # underscore module mapped to dist name
    assert "transformers" in targets


def test_model_targets_only_repo_ids() -> None:
    result = scan_path(REPO)
    targets = model_targets(result)
    # sentence-transformers/... is a repo id; gpt-4o and claude-* are not.
    assert "sentence-transformers/all-MiniLM-L6-v2" in targets
    assert "gpt-4o" not in targets


def test_enrich_scan_end_to_end(tmp_path: Path) -> None:
    result = scan_path(REPO / "store.py")  # pinecone only — small, predictable
    fetcher = FakeFetcher(
        {
            "https://pypi.org/pypi/pinecone/json": ok(
                {"info": {"version": "5.0.0", "license": "Apache-2.0"}}
            ),
            "https://api.osv.dev/v1/query": ok({"vulns": [{"id": "CVE-2024-9"}]}),
        }
    )
    report = enrich_scan(result, fetcher=fetcher, cache=Cache(root=tmp_path), offline=False)
    pkg = report.packages["pinecone"]
    assert pkg.pypi.license == "Apache-2.0"
    assert pkg.pypi.version == "5.0.0"
    assert [v.id for v in pkg.vulns] == ["CVE-2024-9"]
    assert report.total_vulns == 1


def test_models_always_carry_undocumented_provenance(tmp_path: Path) -> None:
    result = scan_path(REPO / "models.py")
    fetcher = FakeFetcher(
        {
            "https://huggingface.co/api/models/sentence-transformers/all-MiniLM-L6-v2": ok(
                {"cardData": {"license": "apache-2.0", "datasets": ["s2orc", "flax-sentence"]}}
            )
        }
    )
    report = enrich_scan(result, fetcher=fetcher, cache=Cache(root=tmp_path), offline=False)
    model = report.models["sentence-transformers/all-MiniLM-L6-v2"]
    # Even with a declared license AND declared datasets, provenance/consent stay UNKNOWN:
    # a declaration is not verification. Honest gaps, never a fake green check.
    assert model.hf.license == "apache-2.0"
    assert model.hf.datasets == ("s2orc", "flax-sentence")
    assert model.provenance == UNDOCUMENTED
    assert model.consent_basis == UNDOCUMENTED


def test_offline_never_calls_fetcher(tmp_path: Path) -> None:
    result = scan_path(REPO / "store.py")
    fetcher = FakeFetcher()  # empty: any real call would 404, but offline must not call
    report = enrich_scan(result, fetcher=fetcher, cache=Cache(root=tmp_path), offline=True)
    assert fetcher.calls == []
    assert report.offline is True
    assert report.packages["pinecone"].pypi.status == EnrichStatus.OFFLINE
