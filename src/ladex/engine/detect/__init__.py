"""Detection: parse code and infrastructure, emit structured AI component records."""

from __future__ import annotations

from ladex.engine.detect.ast_walker import PythonDetector
from ladex.engine.detect.records import Detection, SourceSpan

__all__ = ["Detection", "PythonDetector", "SourceSpan"]
