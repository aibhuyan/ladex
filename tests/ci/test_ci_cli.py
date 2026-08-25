"""The `ladex ci` CLI surface: formats and gating exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ladex.cli import main

MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def _repo(tmp_path: Path) -> str:
    (tmp_path / "app.py").write_text(f'EMBED = "{MODEL}"\nimport transformers\n', encoding="utf-8")
    return str(tmp_path)


def test_ci_exit_code_fails_on_gaps(tmp_path: Path) -> None:
    assert main(["ci", _repo(tmp_path)]) == 1  # default --fail-on gaps, provenance gap present


def test_ci_fail_on_none_always_zero(tmp_path: Path) -> None:
    assert main(["ci", _repo(tmp_path), "--fail-on", "none"]) == 0


def test_ci_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["ci", _repo(tmp_path), "--format", "json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is False
    assert any(g["subject"] == MODEL for g in payload["gaps"])


def test_ci_markdown(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["ci", _repo(tmp_path), "--format", "markdown", "--fail-on", "none"])
    out = capsys.readouterr().out
    assert out.startswith("## Ladex")
    assert "ladex attest" in out


def test_ci_github_writes_step_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    rc = main(["ci", _repo(tmp_path), "--format", "github"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "::warning" in out  # inline annotation for the gap
    assert "Ladex" in summary.read_text(encoding="utf-8")


def test_ci_clean_repo_passes(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert main(["ci", str(tmp_path)]) == 0
