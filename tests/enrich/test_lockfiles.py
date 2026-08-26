"""Version-accurate enrichment: pin package versions from lockfiles for correct CVEs."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.enrich.lockfiles import normalize, resolve_versions
from ladex.engine.enrich.models import EnrichStatus
from ladex.engine.enrich.service import enrich_scan
from ladex.engine.scan import scan_path

from .conftest import FakeFetcher, ok


def test_normalize() -> None:
    assert normalize("Huggingface_Hub") == "huggingface-hub"
    assert normalize("qdrant_client") == "qdrant-client"


def test_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "openai"\nversion = "1.2.3"\n\n'
        '[[package]]\nname = "transformers"\nversion = "4.38.0"\n',
        encoding="utf-8",
    )
    v = resolve_versions(tmp_path)
    assert v["openai"] == ("1.2.3", "uv.lock")
    assert v["transformers"] == ("4.38.0", "uv.lock")


def test_requirements_txt(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "openai==1.5.0\n"
        "# a comment\n"
        "chromadb[server]==0.5.0 ; python_version>='3.9'\n"
        "-r other.txt\n",
        encoding="utf-8",
    )
    v = resolve_versions(tmp_path)
    assert v["openai"] == ("1.5.0", "requirements.txt")
    assert v["chromadb"] == ("0.5.0", "requirements.txt")


def test_priority_uv_over_requirements(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "openai"\nversion = "9.9.9"\n', "utf-8")
    (tmp_path / "requirements.txt").write_text("openai==1.0.0\n", encoding="utf-8")
    assert resolve_versions(tmp_path)["openai"] == ("9.9.9", "uv.lock")


def test_missing_lockfiles_is_empty(tmp_path: Path) -> None:
    assert resolve_versions(tmp_path) == {}


def test_enrich_uses_pinned_version_for_cves(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import openai\nopenai.OpenAI()\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text('[[package]]\nname = "openai"\nversion = "1.2.3"\n', "utf-8")
    fetcher = FakeFetcher(
        {
            # PyPI says latest is 9.9.9, but the project pins 1.2.3.
            "https://pypi.org/pypi/openai/json": ok(
                {"info": {"version": "9.9.9", "license": "MIT"}}
            ),
            "https://api.osv.dev/v1/query": ok({"vulns": [{"id": "CVE-PINNED"}]}),
        }
    )
    from ladex.engine.enrich.cache import Cache

    report = enrich_scan(
        scan_path(tmp_path), fetcher=fetcher, cache=Cache(root=tmp_path / "c"), root=tmp_path
    )
    pkg = report.packages["openai"]
    assert pkg.effective_version == "1.2.3"  # pinned, not PyPI latest
    assert pkg.resolved_version == "1.2.3"
    assert pkg.version_source == "uv.lock"
    assert any("api.osv.dev" in c for c in fetcher.calls)  # CVEs queried
    assert [v.id for v in pkg.vulns] == ["CVE-PINNED"]
    assert pkg.vulns_status is EnrichStatus.LIVE


def test_enrich_falls_back_to_latest_when_unpinned(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import openai\nopenai.OpenAI()\n", encoding="utf-8")
    fetcher = FakeFetcher(
        {
            "https://pypi.org/pypi/openai/json": ok(
                {"info": {"version": "9.9.9", "license": "MIT"}}
            ),
            "https://api.osv.dev/v1/query": ok({}),
        }
    )
    from ladex.engine.enrich.cache import Cache

    report = enrich_scan(
        scan_path(tmp_path), fetcher=fetcher, cache=Cache(root=tmp_path / "c"), root=tmp_path
    )
    pkg = report.packages["openai"]
    assert pkg.resolved_version is None
    assert pkg.effective_version == "9.9.9"
    assert pkg.version_source == "pypi-latest"
