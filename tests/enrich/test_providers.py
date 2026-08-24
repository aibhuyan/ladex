"""Provider parsing: PyPI, OSV, and HF Hub payloads → typed enrichment models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ladex.engine.enrich import osv, pypi
from ladex.engine.enrich.cache import Cache
from ladex.engine.enrich.hfhub import fetch_model, looks_like_repo_id
from ladex.engine.enrich.http import FetchResult
from ladex.engine.enrich.models import EnrichStatus

from .conftest import FakeFetcher, ok


def _cache(tmp_path: Path) -> Cache:
    return Cache(root=tmp_path)


# -- PyPI ------------------------------------------------------------------


def test_pypi_license_from_info(tmp_path: Path) -> None:
    fetcher = FakeFetcher(
        {"https://pypi.org/pypi/openai/json": ok({"info": {"version": "1.2.3", "license": "MIT"}})}
    )
    info = pypi.fetch_package("openai", fetcher, _cache(tmp_path), offline=False)
    assert info.version == "1.2.3"
    assert info.license == "MIT"
    assert info.status == EnrichStatus.LIVE


def test_pypi_license_falls_back_to_classifier(tmp_path: Path) -> None:
    fetcher = FakeFetcher(
        {
            "https://pypi.org/pypi/x/json": ok(
                {
                    "info": {
                        "version": "1.0",
                        "license": "",
                        "classifiers": ["License :: OSI Approved :: Apache Software License"],
                    }
                }
            )
        }
    )
    info = pypi.fetch_package("x", fetcher, _cache(tmp_path), offline=False)
    assert info.license == "Apache Software License"


def test_module_to_distribution_mapping() -> None:
    assert pypi.module_to_distribution("huggingface_hub") == "huggingface-hub"
    assert pypi.module_to_distribution("langchain_openai") == "langchain-openai"
    assert pypi.module_to_distribution("openai") == "openai"


def test_pypi_missing_package_is_not_found(tmp_path: Path) -> None:
    info = pypi.fetch_package("nope", FakeFetcher(), _cache(tmp_path), offline=False)
    assert info.status == EnrichStatus.NOT_FOUND
    assert info.license is None


# -- OSV -------------------------------------------------------------------


def test_osv_parses_vulns(tmp_path: Path) -> None:
    fetcher = FakeFetcher(
        {
            "https://api.osv.dev/v1/query": ok(
                {
                    "vulns": [
                        {"id": "GHSA-xxxx", "aliases": ["CVE-2024-1"], "summary": "bad"},
                        {"id": "PYSEC-1"},
                    ]
                }
            )
        }
    )
    vulns, status = osv.fetch_vulns("openai", "1.0", fetcher, _cache(tmp_path), offline=False)
    assert status == EnrichStatus.LIVE
    assert {v.id for v in vulns} == {"GHSA-xxxx", "PYSEC-1"}
    assert vulns[0].aliases == ("CVE-2024-1",)


def test_osv_no_vulns(tmp_path: Path) -> None:
    fetcher = FakeFetcher({"https://api.osv.dev/v1/query": ok({})})
    vulns, status = osv.fetch_vulns("safe", "1.0", fetcher, _cache(tmp_path), offline=False)
    assert vulns == ()
    assert status == EnrichStatus.LIVE


# -- HF Hub ----------------------------------------------------------------


def test_repo_id_heuristic() -> None:
    assert looks_like_repo_id("sentence-transformers/all-MiniLM-L6-v2")
    assert not looks_like_repo_id("gpt-4o")
    assert not looks_like_repo_id("a/b/c")


def test_hfhub_parses_card(tmp_path: Path) -> None:
    fetcher = FakeFetcher(
        {
            "https://huggingface.co/api/models/org/model": ok(
                {
                    "downloads": 999,
                    "gated": False,
                    "tags": ["license:apache-2.0"],
                    "cardData": {
                        "license": "apache-2.0",
                        "base_model": "bert-base-uncased",
                        "datasets": ["squad"],
                    },
                }
            )
        }
    )
    info = fetch_model("org/model", fetcher, _cache(tmp_path), offline=False)
    assert info.license == "apache-2.0"
    assert info.base_model == "bert-base-uncased"
    assert info.datasets == ("squad",)
    assert info.downloads == 999


def test_hfhub_token_is_sent_as_auth_header(tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class CapturingFetcher(FakeFetcher):
        def fetch_json(
            self,
            url: str,
            *,
            method: str = "GET",
            json_body: dict[str, Any] | None = None,
            headers: dict[str, str] | None = None,
        ) -> FetchResult:
            captured["headers"] = headers
            return ok({"cardData": {}})

    fetch_model("org/m", CapturingFetcher(), _cache(tmp_path), offline=False, token="secret")
    assert captured["headers"] == {"Authorization": "Bearer secret"}
