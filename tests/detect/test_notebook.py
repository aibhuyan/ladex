"""Jupyter notebook detection: code cells, cell indexing, and error tolerance."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.detect import PythonDetector
from ladex.engine.detect.notebook import detect_notebook_file, detect_notebook_source
from ladex.engine.scan import scan_path

NB = Path(__file__).parent.parent / "fixtures" / "notebooks" / "demo.ipynb"


def _detector() -> PythonDetector:
    return PythonDetector()


def test_detects_across_code_cells() -> None:
    dets = detect_notebook_file(NB, _detector())
    ids = {d.rule_id for d in dets}
    assert {"openai.import", "openai.client", "openai.model-id"} <= ids


def test_cell_index_is_recorded() -> None:
    dets = detect_notebook_file(NB, _detector())
    imp = next(d for d in dets if d.rule_id == "openai.import")
    assert imp.cell == 2  # markdown is cell 1; first code cell is 2
    model = next(d for d in dets if d.rule_id == "openai.model-id")
    assert model.cell == 3
    assert "cell2" in imp.location()


def test_source_as_string_or_list() -> None:
    # cell 3 uses a plain-string source; cell 2 uses a list of lines — both must work.
    dets = detect_notebook_file(NB, _detector())
    cells = {d.cell for d in dets}
    assert {2, 3} <= cells


def test_markdown_and_noise_cells_are_silent() -> None:
    dets = detect_notebook_file(NB, _detector())
    # The json cell (cell 4) and the markdown cell (cell 1) produce nothing.
    assert all(d.cell in {2, 3} for d in dets)


def test_invalid_notebook_does_not_raise() -> None:
    assert detect_notebook_source("{ not valid json", "x.ipynb", _detector()) == []
    assert detect_notebook_source('{"cells": "nope"}', "x.ipynb", _detector()) == []


def test_scan_includes_notebooks() -> None:
    result = scan_path(NB.parent)
    assert any(d.cell is not None for d in result.detections)
    assert "openai.client" in {d.rule_id for d in result.detections}
