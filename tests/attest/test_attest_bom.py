"""Attestations flow into the BOM only when their signatures verify."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from ladex.engine.attest import LocalSigner, create_attestation
from ladex.engine.bom import build_bom, render_json
from ladex.engine.scan import scan_path

REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"
MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def _model_props(doc: dict[str, Any], name: str) -> dict[str, str]:
    comp = next(c for c in doc["components"] if c["name"] == name)
    return {p["name"]: p["value"] for p in comp["properties"]}


def test_verified_attestation_fills_the_gap(tmp_path: Path) -> None:
    signer = LocalSigner(key_path=tmp_path / "key")
    att = create_attestation(MODEL, "provenance", "Curated public corpora, 2024", "dev@x", signer)
    result = scan_path(REPO)
    doc = json.loads(render_json(build_bom(result, attestations=[att], project_name="s")))
    props = _model_props(doc, MODEL)
    assert props["ladex:provenance"] == "Curated public corpora, 2024"
    assert props["ladex:provenance.attester"] == "dev@x"
    assert "ladex:provenance.attestation" in props
    # The unattested claim is still honestly UNDOCUMENTED.
    assert props["ladex:consent_basis"] == "UNDOCUMENTED"


def test_invalid_attestation_is_ignored(tmp_path: Path) -> None:
    signer = LocalSigner(key_path=tmp_path / "key")
    att = create_attestation(MODEL, "provenance", "real", "dev@x", signer)
    forged = dataclasses.replace(att, value="FORGED")
    result = scan_path(REPO)
    doc = json.loads(render_json(build_bom(result, attestations=[forged], project_name="s")))
    props = _model_props(doc, MODEL)
    # A tampered attestation must NOT fill the gap — stays UNDOCUMENTED.
    assert props["ladex:provenance"] == "UNDOCUMENTED"


def test_bom_with_attestation_is_deterministic(tmp_path: Path) -> None:
    signer = LocalSigner(key_path=tmp_path / "key")
    att = create_attestation(
        MODEL, "provenance", "v", "dev@x", signer, created="2026-01-01T00:00:00+00:00"
    )
    result = scan_path(REPO)
    a = render_json(build_bom(result, attestations=[att], project_name="s"))
    b = render_json(build_bom(result, attestations=[att], project_name="s"))
    assert a == b
