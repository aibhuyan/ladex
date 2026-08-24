"""Directory scanning: file discovery, ignore rules, aggregation, and summaries."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.scan import DEFAULT_IGNORE_DIRS, iter_python_files, scan_path

REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


def test_iter_finds_fixture_files() -> None:
    names = {p.name for p in iter_python_files(REPO)}
    assert {"agents.py", "models.py", "store.py", "noise.py", "broken.py"} <= names


def test_iter_prunes_ignored_and_hidden_dirs(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("import openai\n", encoding="utf-8")
    for bad in (".venv", "node_modules", ".hidden"):
        d = tmp_path / bad
        d.mkdir()
        (d / "buried.py").write_text("import openai\n", encoding="utf-8")
    found = {p.name for p in iter_python_files(tmp_path)}
    assert found == {"keep.py"}
    assert ".venv" in DEFAULT_IGNORE_DIRS


def test_iter_single_file() -> None:
    assert [p.name for p in iter_python_files(REPO / "agents.py")] == ["agents.py"]


def test_scan_aggregates_across_files() -> None:
    result = scan_path(REPO)
    assert result.files_scanned == 5
    rule_ids = {d.rule_id for d in result.detections}
    assert "openai.import" in rule_ids  # from agents.py
    assert "transformers.pipeline" in rule_ids  # from models.py
    assert "pinecone.client" in rule_ids  # from store.py


def test_scan_is_deterministic() -> None:
    assert scan_path(REPO).detections == scan_path(REPO).detections


def test_scan_summaries() -> None:
    result = scan_path(REPO)
    by_type = result.counts_by_component_type()
    assert by_type.get("inference_api", 0) >= 2
    by_provider = result.counts_by_provider()
    assert "OpenAI" in by_provider
    # noise.py contributes nothing, so fewer files have findings than were scanned.
    assert result.files_with_findings < result.files_scanned


def test_empty_dir_scans_clean(tmp_path: Path) -> None:
    result = scan_path(tmp_path)
    assert result.files_scanned == 0
    assert result.detections == ()
