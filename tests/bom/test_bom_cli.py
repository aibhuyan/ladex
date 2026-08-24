"""The `ladex scan --write-bom` CLI surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ladex.cli import main

REPO = str(Path(__file__).parent.parent / "fixtures" / "sample_repo")


def test_write_bom_creates_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "aibom.cdx.json"
    rc = main(["scan", REPO, "--write-bom", str(out)])
    assert rc == 0
    assert "wrote" in capsys.readouterr().out
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["components"]


def test_write_bom_is_stable_across_runs(tmp_path: Path) -> None:
    out = tmp_path / "aibom.cdx.json"
    main(["scan", REPO, "--write-bom", str(out)])
    first = out.read_text(encoding="utf-8")
    main(["scan", REPO, "--write-bom", str(out)])
    second = out.read_text(encoding="utf-8")
    assert first == second  # commits and diffs cleanly
