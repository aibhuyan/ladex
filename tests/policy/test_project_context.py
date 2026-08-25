"""The declared project profile (.ladex/project.yaml) and CLI-over-file merge."""

from __future__ import annotations

from pathlib import Path

import pytest

from ladex.engine.policy import (
    ProjectContext,
    ProjectContextError,
    load_project_context,
    project_template,
)


def _write(root: Path, text: str) -> None:
    (root / ".ladex").mkdir(parents=True, exist_ok=True)
    (root / ".ladex" / "project.yaml").write_text(text, encoding="utf-8")


def test_absent_file_is_empty_context(tmp_path: Path) -> None:
    ctx = load_project_context(tmp_path)
    assert ctx.user_facing is None and ctx.high_risk is None


def test_loads_declared_facts(tmp_path: Path) -> None:
    _write(tmp_path, "version: 1\nuser_facing: true\nhigh_risk: false\ngpai_provider: true\n")
    ctx = load_project_context(tmp_path)
    assert ctx.user_facing is True
    assert ctx.high_risk is False
    assert ctx.gpai_provider is True
    assert ctx.emotion_recognition is None  # undeclared stays unknown


def test_unknown_fact_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "version: 1\nteleporter: true\n")
    with pytest.raises(ProjectContextError, match="unknown project fact"):
        load_project_context(tmp_path)


def test_non_bool_value_rejected(tmp_path: Path) -> None:
    _write(tmp_path, "version: 1\nuser_facing: maybe\n")
    with pytest.raises(ProjectContextError, match="true, false, or omitted"):
        load_project_context(tmp_path)


def test_cli_override_wins_over_file(tmp_path: Path) -> None:
    _write(tmp_path, "version: 1\nuser_facing: false\n")
    base = load_project_context(tmp_path)
    merged = base.merge(ProjectContext(user_facing=True))
    assert merged.user_facing is True  # override wins
    # A None override leaves the file value intact.
    merged2 = base.merge(ProjectContext(user_facing=None))
    assert merged2.user_facing is False


def test_template_is_valid_yaml_and_parses(tmp_path: Path) -> None:
    _write(tmp_path, project_template())
    ctx = load_project_context(tmp_path)  # all facts commented out -> all None
    assert all(ctx.get(k) is None for k in ("user_facing", "high_risk", "gpai_provider"))
