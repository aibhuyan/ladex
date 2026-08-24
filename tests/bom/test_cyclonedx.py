"""CycloneDX ML-BOM: determinism, structure, honest-gaps, and schema validity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ladex.engine.bom import build_bom, render_json
from ladex.engine.enrich.models import (
    EnrichedModel,
    EnrichedPackage,
    EnrichmentReport,
    EnrichStatus,
    ModelInfo,
    PyPIInfo,
    Vuln,
)
from ladex.engine.policy import check_scan
from ladex.engine.scan import scan_path

REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


def _bom_dict(**kwargs: object) -> dict[str, Any]:
    result = scan_path(REPO)
    bom = build_bom(result, project_name="sample", **kwargs)  # type: ignore[arg-type]
    doc: dict[str, Any] = json.loads(render_json(bom))
    return doc


def test_bom_is_wellformed_cyclonedx() -> None:
    doc = _bom_dict()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["metadata"]["component"]["name"] == "sample"
    tool_names = {t["name"] for t in doc["metadata"]["tools"]["components"]}
    assert "ladex" in tool_names


def test_bom_has_package_and_model_components() -> None:
    doc = _bom_dict()
    by_type: dict[str, set[str]] = {}
    for comp in doc["components"]:
        by_type.setdefault(comp["type"], set()).add(comp["name"])
    assert "openai" in by_type["library"]
    assert "huggingface-hub" in by_type["library"]  # dist name, not module name
    assert any("MiniLM" in n for n in by_type["machine-learning-model"])


def test_models_carry_undocumented_provenance() -> None:
    doc = _bom_dict()
    models = [c for c in doc["components"] if c["type"] == "machine-learning-model"]
    assert models
    for model in models:
        props = {p["name"]: p["value"] for p in model.get("properties", [])}
        assert props["ladex:provenance"] == "UNDOCUMENTED"
        assert props["ladex:consent_basis"] == "UNDOCUMENTED"


def test_output_is_deterministic() -> None:
    result = scan_path(REPO)
    a = render_json(build_bom(result, project_name="sample"))
    b = render_json(build_bom(result, project_name="sample"))
    assert a == b


def test_enrichment_adds_license_version_and_cves() -> None:
    enrichment = EnrichmentReport(
        offline=False,
        packages={
            "openai": EnrichedPackage(
                name="openai",
                pypi=PyPIInfo(
                    name="openai", status=EnrichStatus.LIVE, version="1.2.3", license="MIT"
                ),
                vulns=(Vuln(id="CVE-2024-1"),),
                vulns_status=EnrichStatus.LIVE,
            )
        },
        models={},
    )
    doc = _bom_dict(enrichment=enrichment)
    openai = next(c for c in doc["components"] if c["name"] == "openai")
    assert openai["version"] == "1.2.3"
    assert openai["purl"] == "pkg:pypi/openai@1.2.3"
    assert openai["licenses"][0]["license"]["id"] == "MIT"
    props = {p["name"]: p["value"] for p in openai["properties"]}
    assert props.get("ladex:cve") == "CVE-2024-1"


def test_model_enrichment_keeps_provenance_undocumented() -> None:
    enrichment = EnrichmentReport(
        offline=False,
        packages={},
        models={
            "sentence-transformers/all-MiniLM-L6-v2": EnrichedModel(
                repo_id="sentence-transformers/all-MiniLM-L6-v2",
                hf=ModelInfo(
                    repo_id="sentence-transformers/all-MiniLM-L6-v2",
                    status=EnrichStatus.LIVE,
                    license="apache-2.0",
                    base_model="nreimers/MiniLM-L6",
                ),
            )
        },
    )
    doc = _bom_dict(enrichment=enrichment)
    model = next(
        c for c in doc["components"] if c["name"] == "sentence-transformers/all-MiniLM-L6-v2"
    )
    props = {p["name"]: p["value"] for p in model["properties"]}
    assert props["ladex:base_model"] == "nreimers/MiniLM-L6"
    # Declared license is fine; provenance stays UNDOCUMENTED even with enrichment.
    assert props["ladex:provenance"] == "UNDOCUMENTED"
    assert model["externalReferences"][0]["url"].startswith("https://huggingface.co/")


def test_policy_obligations_recorded_in_metadata() -> None:
    result = scan_path(REPO)
    policy = check_scan(result)
    doc = json.loads(render_json(build_bom(result, policy=policy, project_name="sample")))
    props = {p["name"] for p in doc["metadata"].get("properties", [])}
    assert any(n.startswith("ladex:obligation:art-50") for n in props)


def test_bom_validates_against_schema() -> None:
    from cyclonedx.schema import OutputFormat, SchemaVersion
    from cyclonedx.validation import make_schemabased_validator

    result = scan_path(REPO)
    bom_json = render_json(build_bom(result, project_name="sample"))
    validator = make_schemabased_validator(OutputFormat.JSON, SchemaVersion.V1_6)
    assert validator.validate_str(bom_json) is None  # None == valid
