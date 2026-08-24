"""Structured records emitted by detection.

A :class:`Detection` is one taxonomy rule firing at one location in one file. It is an
*occurrence*, not yet a BOM component — the BOM layer (Step 6) will dedupe detections into
components. Positions use 1-based lines and 0-based columns (the tree-sitter convention,
one subtraction away from LSP's 0-based lines in Step 8).
"""

from __future__ import annotations

from dataclasses import dataclass

from ladex.engine.taxonomy.models import ComponentType


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A half-open span in a source file. Lines are 1-based; columns are 0-based."""

    start_line: int
    start_col: int
    end_line: int
    end_col: int


@dataclass(frozen=True, slots=True)
class Detection:
    """One taxonomy rule matched at one source location."""

    rule_id: str
    name: str
    component_type: ComponentType
    match_kind: str
    evidence: str
    path: str
    span: SourceSpan
    provider: str | None = None
    tags: tuple[str, ...] = ()
    #: For IaC misconfiguration findings: info | low | medium | high. None for code detections.
    severity: str | None = None

    def location(self) -> str:
        """`path:line:col`, clickable in most terminals and editors."""
        return f"{self.path}:{self.span.start_line}:{self.span.start_col + 1}"

    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.path, self.span.start_line, self.span.start_col, self.rule_id)
