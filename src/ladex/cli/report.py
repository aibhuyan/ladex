"""Human- and machine-readable rendering of a :class:`ScanResult` for the CLI surface."""

from __future__ import annotations

import os
from typing import Any

from rich.console import Console
from rich.markup import escape

from ladex.engine.detect import Detection
from ladex.engine.scan import ScanResult

_TYPE_STYLE: dict[str, str] = {
    "inference_api": "cyan",
    "model": "magenta",
    "model_loader": "magenta",
    "agent_framework": "yellow",
    "vector_store": "green",
    "dataset": "blue",
    "embeddings": "blue",
}

_EVIDENCE_MAX = 48


def render_scan(result: ScanResult, console: Console | None = None) -> None:
    """Print a clean, grouped, colorized report of a scan."""
    console = console or Console()

    if not result.detections:
        console.print(
            f"[dim]No AI components found in {result.files_scanned} file(s) under[/dim] "
            f"{escape(str(result.root))}"
        )
        return

    # Align columns across the whole report so files read consistently.
    rule_w = max(len(d.rule_id) for d in result.detections)
    type_w = max(len(d.component_type.value) for d in result.detections)

    for path, dets in result.detections_by_file().items():
        console.print(f"\n[bold]{escape(_relativize(path, result.root))}[/bold]")
        for det in dets:
            console.print("  " + _render_row(det, rule_w, type_w))

    _render_summary(result, console)


def _render_row(det: Detection, rule_w: int, type_w: int) -> str:
    loc = f"{det.span.start_line}:{det.span.start_col + 1}"
    style = _TYPE_STYLE.get(det.component_type.value, "white")
    type_cell = f"{det.component_type.value:<{type_w}}"
    rule_cell = f"{det.rule_id:<{rule_w}}"
    evidence = escape(_truncate(det.evidence, _EVIDENCE_MAX))
    provider = f" [dim]({escape(det.provider)})[/dim]" if det.provider else ""
    return (
        f"[dim]{loc:>7}[/dim]  [{style}]{type_cell}[/{style}]  "
        f"[bold]{rule_cell}[/bold]  {evidence}{provider}"
    )


def _render_summary(result: ScanResult, console: Console) -> None:
    console.print(
        f"\n[bold]Summary:[/bold] {len(result.detections)} detection(s) across "
        f"{result.files_with_findings} of {result.files_scanned} file(s) scanned."
    )
    by_type = result.counts_by_component_type()
    if by_type:
        parts = "   ".join(f"[bold]{k}[/bold]: {v}" for k, v in by_type.items())
        console.print(f"  {parts}")


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _relativize(path: str, root: os.PathLike[str]) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:  # different drive on Windows
        return path


def scan_to_dict(result: ScanResult) -> dict[str, Any]:
    """Serialize a scan result to a plain dict for ``--json`` output."""
    return {
        "root": str(result.root),
        "files_scanned": result.files_scanned,
        "files_with_findings": result.files_with_findings,
        "summary": {
            "by_component_type": result.counts_by_component_type(),
            "by_provider": result.counts_by_provider(),
        },
        "detections": [_detection_to_dict(d) for d in result.detections],
    }


def _detection_to_dict(det: Detection) -> dict[str, Any]:
    return {
        "rule_id": det.rule_id,
        "name": det.name,
        "component_type": det.component_type.value,
        "provider": det.provider,
        "match_kind": det.match_kind,
        "evidence": det.evidence,
        "path": det.path,
        "line": det.span.start_line,
        "column": det.span.start_col,
        "end_line": det.span.end_line,
        "end_column": det.span.end_col,
        "tags": list(det.tags),
    }
