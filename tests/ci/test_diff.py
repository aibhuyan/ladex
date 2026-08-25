"""BOM-diff: component delta between a base and a head scan."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.ci import build_ci_report
from ladex.engine.diff import diff_scans, render_diff_markdown
from ladex.engine.policy import ProjectContext
from ladex.engine.scan import scan_path


def _base(tmp_path: Path) -> Path:
    d = tmp_path / "base"
    d.mkdir()
    (d / "app.py").write_text("import openai\nopenai.OpenAI()\n", encoding="utf-8")
    return d


def _head(tmp_path: Path) -> Path:
    d = tmp_path / "head"
    d.mkdir()
    # openai stays; a model + chroma are added; (openai client remains)
    (d / "app.py").write_text(
        'import openai\nopenai.OpenAI()\nEMBED = "sentence-transformers/all-MiniLM-L6-v2"\n'
        "import chromadb\nchromadb.PersistentClient(path='db')\n",
        encoding="utf-8",
    )
    return d


def test_diff_reports_added_components(tmp_path: Path) -> None:
    diff = diff_scans(scan_path(_base(tmp_path)), scan_path(_head(tmp_path)))
    added = {c.label for c in diff.added}
    assert "sentence-transformers/all-MiniLM-L6-v2" in added
    assert any("Chroma" in a for a in added)
    assert diff.removed == ()  # openai still present


def test_diff_reports_removed_components(tmp_path: Path) -> None:
    # Head is the smaller one -> openai is removed.
    diff = diff_scans(scan_path(_head(tmp_path)), scan_path(_base(tmp_path)))
    removed = {c.label for c in diff.removed}
    assert any("Chroma" in r for r in removed)
    assert "sentence-transformers/all-MiniLM-L6-v2" in removed


def test_no_change_diff(tmp_path: Path) -> None:
    base = _base(tmp_path)
    diff = diff_scans(scan_path(base), scan_path(base))
    assert not diff.changed
    assert "No AI components added or removed" in render_diff_markdown(diff)


def test_markdown_lists_added(tmp_path: Path) -> None:
    diff = diff_scans(scan_path(_base(tmp_path)), scan_path(_head(tmp_path)))
    md = render_diff_markdown(diff)
    assert "added" in md
    assert "sentence-transformers/all-MiniLM-L6-v2" in md


def test_ci_report_includes_diff(tmp_path: Path) -> None:
    report = build_ci_report(_head(tmp_path), ProjectContext(), base=_base(tmp_path))
    assert report.diff is not None
    assert any("MiniLM" in c.label for c in report.diff.added)
