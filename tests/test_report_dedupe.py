"""Report dedupe: repeated (rule, evidence) within a file collapse to one row with xN."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from ladex.cli.report import _dedupe, render_scan
from ladex.engine.detect.records import Detection, SourceSpan
from ladex.engine.scan import ScanResult
from ladex.engine.taxonomy.models import ComponentType


def _det(rule: str, evidence: str, line: int) -> Detection:
    return Detection(
        rule_id=rule,
        name=rule,
        component_type=ComponentType.MODEL,
        match_kind="string",
        evidence=evidence,
        path="app.py",
        span=SourceSpan(line, 0, line, 5),
    )


def test_dedupe_collapses_repeats_keeping_first() -> None:
    dets = [
        _det("hf-model", "gpt2", 1),
        _det("hf-model", "gpt2", 10),
        _det("hf-model", "gpt2", 20),
        _det("hf-model", "bert", 5),
    ]
    collapsed = _dedupe(dets)
    assert [(d.evidence, n) for d, n in collapsed] == [("gpt2", 3), ("bert", 1)]
    # keeps the first occurrence's location
    assert collapsed[0][0].span.start_line == 1


def test_render_shows_times_marker() -> None:
    result = ScanResult(
        root=Path("."),
        files_scanned=1,
        detections=(_det("hf-model", "gpt2", 1), _det("hf-model", "gpt2", 9)),
    )
    buf = StringIO()
    render_scan(result, Console(file=buf, width=100, force_terminal=False))
    out = buf.getvalue()
    assert "x2" in out
    # only one row for the repeated model
    assert out.count("gpt2") == 1
