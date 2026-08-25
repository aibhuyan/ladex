"""Jupyter notebook (.ipynb) detection.

A notebook is JSON with a ``cells`` array; code cells carry Python in ``source`` (a list of
lines or a string). We run the *same* :class:`PythonDetector` over each code cell's source and
stamp each detection with its 1-based cell index, so findings point at the cell you'd scroll
to. Reusing the Python detector keeps notebooks consistent with ``.py`` files — one engine.

Error-tolerant like the rest of detection: malformed JSON (or a non-notebook ``.ipynb``)
yields no detections rather than raising.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from ladex.engine.detect.ast_walker import PythonDetector
from ladex.engine.detect.records import Detection


def _cell_source(cell: dict[str, Any]) -> str:
    src = cell.get("source", "")
    if isinstance(src, list):
        return "".join(str(s) for s in src)
    return str(src)


def detect_notebook_source(text: str, path: str, detector: PythonDetector) -> list[Detection]:
    """Detect AI components across the code cells of a notebook given its JSON text."""
    try:
        nb = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(nb, dict):
        return []
    cells = nb.get("cells")
    if not isinstance(cells, list):
        return []

    out: list[Detection] = []
    for index, cell in enumerate(cells, start=1):  # 1-based, includes markdown cells
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        source = _cell_source(cell)
        if not source.strip():
            continue
        for det in detector.detect_source(source, path):
            out.append(dataclasses.replace(det, cell=index))
    out.sort(key=Detection.sort_key)
    return out


def detect_notebook_file(path: Path, detector: PythonDetector) -> list[Detection]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return detect_notebook_source(text, str(path), detector)
