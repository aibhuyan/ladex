"""The `ladex init` CLI surface: scaffold project.yaml + the PR-check workflow."""

from __future__ import annotations

from pathlib import Path

import pytest

from ladex.cli import main


def test_init_scaffolds_both_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["init", str(tmp_path)])
    assert rc == 0
    project = tmp_path / ".ladex" / "project.yaml"
    workflow = tmp_path / ".github" / "workflows" / "ladex.yml"
    assert project.exists()
    assert workflow.exists()
    out = capsys.readouterr().out
    assert "created .ladex/project.yaml" in out
    assert "created .github/workflows/ladex.yml" in out


def test_init_workflow_pins_the_action(tmp_path: Path) -> None:
    main(["init", str(tmp_path)])
    text = (tmp_path / ".github" / "workflows" / "ladex.yml").read_text(encoding="utf-8")
    from ladex import __version__

    assert f"aibhuyan/ladex/apps/github@v{__version__}" in text
    assert "pull_request" in text


def test_init_is_idempotent_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["init", str(tmp_path)])
    marker = "# my edits\n"
    project = tmp_path / ".ladex" / "project.yaml"
    project.write_text(marker, encoding="utf-8")

    capsys.readouterr()  # drop first-run output
    rc = main(["init", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "kept existing .ladex/project.yaml" in out
    assert project.read_text(encoding="utf-8") == marker  # untouched
