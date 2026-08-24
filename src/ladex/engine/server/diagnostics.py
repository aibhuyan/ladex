"""Map detections to LSP diagnostics — the pure, testable core of the IDE surface.

This deliberately calls the *same* :class:`PythonDetector` the CLI and PR check use, so the
editor can never disagree with the gate ("one engine, three surfaces"). It is a plain
function of ``(text) -> list[Diagnostic]`` with no server state, so it is unit-testable
without a running language server.

Diagnostics are informational, never errors — Ladex records what's aboard, it doesn't block.
The message answers "what is this?" and nudges "what might it obligate?" inline.
"""

from __future__ import annotations

from lsprotocol import types

from ladex.engine.detect import Detection, PythonDetector
from ladex.engine.taxonomy.models import ComponentType

_SOURCE = "ladex"

# A short, inline "what might it obligate?" nudge per component type. The authoritative
# answer is the policy layer; this is only a cue while typing.
_OBLIGATION_HINT: dict[ComponentType, str] = {
    ComponentType.INFERENCE_API: "EU AI Act Art. 50 disclosure may apply if user-facing",
    ComponentType.AGENT_FRAMEWORK: "EU AI Act Art. 50 disclosure may apply if user-facing",
    ComponentType.MODEL: "provenance & consent basis need attestation",
    ComponentType.MODEL_LOADER: "loads model weights — provenance needs attestation",
    ComponentType.VECTOR_STORE: "retrieval store — review data residency",
}


def build_diagnostics(text: str, detector: PythonDetector | None = None) -> list[types.Diagnostic]:
    """Detect AI components in ``text`` and return them as LSP diagnostics."""
    det = detector if detector is not None else PythonDetector()
    return [_to_diagnostic(d) for d in det.detect_source(text)]


def _to_diagnostic(d: Detection) -> types.Diagnostic:
    # Our spans are 1-based lines / 0-based cols; LSP is 0-based on both axes.
    start = types.Position(line=d.span.start_line - 1, character=d.span.start_col)
    end = types.Position(line=d.span.end_line - 1, character=d.span.end_col)
    return types.Diagnostic(
        range=types.Range(start=start, end=end),
        message=_message(d),
        severity=types.DiagnosticSeverity.Information,
        source=_SOURCE,
        code=d.rule_id,
    )


def _message(d: Detection) -> str:
    who = f" [{d.provider}]" if d.provider else ""
    head = f"{d.name}{who} — {d.component_type.value}"
    hint = _OBLIGATION_HINT.get(d.component_type)
    return f"{head}. {hint}." if hint else head
