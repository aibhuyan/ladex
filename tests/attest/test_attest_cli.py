"""The `ladex attest` / `ladex verify` CLI surface and its BOM integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ladex.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_repo"
MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def _seed_repo(tmp_path: Path) -> Path:
    """A tiny repo that references the model, plus its own HOME for the signing key."""
    (tmp_path / "app.py").write_text(f'EMBED = "{MODEL}"\nimport transformers\n', encoding="utf-8")
    return tmp_path


def test_attest_then_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _seed_repo(tmp_path)
    rc = main(
        [
            "attest",
            MODEL,
            "--claim",
            "provenance",
            "--value",
            "public data",
            "--attester",
            "dev@example.com",
            "--path",
            str(repo),
        ]
    )
    assert rc == 0
    assert "attested provenance" in capsys.readouterr().out
    assert (repo / ".ladex" / "attestations.json").exists()

    rc = main(["verify", str(repo)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1 valid, 0 invalid" in out


def test_attest_requires_value(tmp_path: Path) -> None:
    rc = main(["attest", MODEL, "--claim", "provenance", "--path", str(tmp_path)])
    assert rc == 2


def test_attest_rejects_unknown_claim(tmp_path: Path) -> None:
    rc = main(["attest", MODEL, "--claim", "vibes", "--value", "x", "--path", str(tmp_path)])
    assert rc == 2


def test_verify_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["verify", str(tmp_path)])
    assert rc == 0
    assert "no attestations" in capsys.readouterr().out


def test_attest_shows_up_in_bom(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _seed_repo(tmp_path)
    main(
        [
            "attest",
            MODEL,
            "--claim",
            "provenance",
            "--value",
            "sourced from public web, 2024",
            "--attester",
            "dev@example.com",
            "--path",
            str(repo),
        ]
    )
    capsys.readouterr()
    out_file = tmp_path / "aibom.cdx.json"
    rc = main(["scan", str(repo), "--write-bom", str(out_file)])
    assert rc == 0
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    model = next(c for c in doc["components"] if c["name"] == MODEL)
    props = {p["name"]: p["value"] for p in model["properties"]}
    assert props["ladex:provenance"] == "sourced from public web, 2024"
