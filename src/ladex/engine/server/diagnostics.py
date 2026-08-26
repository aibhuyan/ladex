"""Map detections to LSP diagnostics and quick-fix code actions — the testable IDE core.

Calls the *same* :class:`PythonDetector` the CLI and PR check use, so the editor can never
disagree with the gate. Plain functions of ``(text, ...) -> [...]`` with no server state.

Diagnostics are informational, never errors — Ladex records what's aboard, it doesn't block.
When a project ``root`` is given, model diagnostics become attestation-aware: a model whose
provenance/consent has a verified attestation stops nagging, and unresolved ones offer a
"💡 attest" quick-fix (a code action the VS Code client turns into `ladex attest`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from lsprotocol import types

from ladex.engine.attest import AttestationStore, verify_attestation
from ladex.engine.detect import Detection, PythonDetector
from ladex.engine.enrich.hfhub import looks_like_repo_id
from ladex.engine.taxonomy.models import ComponentType

_SOURCE = "ladex"
ATTEST_COMMAND = "ladex.attest"
_MODEL_CLAIMS = ("provenance", "consent_basis")

#: How much the editor should say. ``actionable`` (default) underlines ONLY detections a human
#: must act on (a loadable model with unattested provenance/consent) — ordinary AI imports and
#: calls stay silent, honouring "ruthless silence" in the editor. ``all`` also surfaces the full
#: inventory, but demoted to a faint ``Hint`` so the actionable squiggles still stand out.
#: ``off`` disables diagnostics entirely.
DiagnosticsMode = Literal["actionable", "all", "off"]
DEFAULT_MODE: DiagnosticsMode = "actionable"

_OBLIGATION_HINT: dict[ComponentType, str] = {
    ComponentType.INFERENCE_API: "EU AI Act Art. 50 disclosure may apply if user-facing",
    ComponentType.AGENT_FRAMEWORK: "EU AI Act Art. 50 disclosure may apply if user-facing",
    ComponentType.MODEL: "provenance & consent basis need attestation",
    ComponentType.MODEL_LOADER: "loads model weights — provenance needs attestation",
    ComponentType.VECTOR_STORE: "retrieval store — review data residency",
}


def _verified_claims(root: Path | None) -> set[tuple[str, str]]:
    if root is None:
        return set()
    return {
        (a.subject, a.claim)
        for a in AttestationStore.for_root(root).load()
        if verify_attestation(a)
    }


def _is_attestable_model(det: Detection) -> bool:
    """A loadable model (HF ``org/name``) whose provenance a human can attest."""
    return det.component_type is ComponentType.MODEL and looks_like_repo_id(det.evidence)


def _unresolved_claims(det: Detection, verified: set[tuple[str, str]]) -> list[str]:
    return [c for c in _MODEL_CLAIMS if (det.evidence, c) not in verified]


def _is_actionable(d: Detection, verified: set[tuple[str, str]]) -> bool:
    """True when a human still has to do something about this detection here and now:
    a loadable model with a provenance/consent claim not yet attested. Everything else is
    inventory — real AI cargo worth recording in the BOM, but nothing to act on in the editor."""
    return _is_attestable_model(d) and bool(_unresolved_claims(d, verified))


def build_diagnostics(
    text: str,
    detector: PythonDetector | None = None,
    root: Path | None = None,
    mode: DiagnosticsMode = DEFAULT_MODE,
) -> list[types.Diagnostic]:
    """Detect AI components in ``text`` and return them as LSP diagnostics.

    ``mode`` controls the editor's noise floor (see :data:`DiagnosticsMode`). Repeats of the
    same (rule, evidence) within the file collapse to their first occurrence — attesting a
    model resolves every use of it at once, so one squiggle per unique component is enough.
    """
    if mode == "off":
        return []
    det = detector if detector is not None else PythonDetector()
    verified = _verified_claims(root)
    diagnostics: list[types.Diagnostic] = []
    seen: set[tuple[str, str]] = set()
    for d in det.detect_source(text):
        actionable = _is_actionable(d, verified)
        if mode == "actionable" and not actionable:
            continue
        key = (d.rule_id, d.evidence)
        if key in seen:
            continue
        seen.add(key)
        diagnostics.append(_to_diagnostic(d, verified, actionable=actionable))
    return diagnostics


def _to_diagnostic(
    d: Detection, verified: set[tuple[str, str]], *, actionable: bool
) -> types.Diagnostic:
    start = types.Position(line=d.span.start_line - 1, character=d.span.start_col)
    end = types.Position(line=d.span.end_line - 1, character=d.span.end_col)
    # Actionable items ask for a decision -> Information (visible, carries the quick-fix).
    # Inventory is demoted to Hint -> a faint marker VS Code keeps out of the Problems noise.
    severity = types.DiagnosticSeverity.Information if actionable else types.DiagnosticSeverity.Hint
    return types.Diagnostic(
        range=types.Range(start=start, end=end),
        message=_message(d, verified),
        severity=severity,
        source=_SOURCE,
        code=d.rule_id,
    )


def _message(d: Detection, verified: set[tuple[str, str]]) -> str:
    who = f" [{d.provider}]" if d.provider else ""
    head = f"{d.name}{who} — {d.component_type.value}"
    if _is_attestable_model(d):
        unresolved = _unresolved_claims(d, verified)
        if not unresolved:
            return f"{head}. provenance & consent basis attested."
        return f"{head}. {', '.join(unresolved)} need attestation."
    hint = _OBLIGATION_HINT.get(d.component_type)
    return f"{head}. {hint}." if hint else head


def code_actions(
    text: str,
    uri: str,
    selection: types.Range,
    root: Path | None = None,
    detector: PythonDetector | None = None,
) -> list[types.CodeAction]:
    """Quick-fix actions for attestable models overlapping the selected range."""
    det = detector if detector is not None else PythonDetector()
    verified = _verified_claims(root)
    actions: list[types.CodeAction] = []
    for d in det.detect_source(text):
        if not _is_attestable_model(d) or not _overlaps(d, selection):
            continue
        for claim in _unresolved_claims(d, verified):
            actions.append(_attest_action(uri, d.evidence, claim))
    return actions


def _overlaps(d: Detection, selection: types.Range) -> bool:
    # Detection spans are 1-based lines; the LSP selection is 0-based.
    det_start = d.span.start_line - 1
    det_end = d.span.end_line - 1
    return det_start <= selection.end.line and selection.start.line <= det_end


def _attest_action(uri: str, subject: str, claim: str) -> types.CodeAction:
    pretty = claim.replace("_", " ")
    args: dict[str, Any] = {"uri": uri, "subject": subject, "claim": claim}
    return types.CodeAction(
        title=f"Ladex: attest {pretty} for {subject}",
        kind=types.CodeActionKind.QuickFix,
        command=types.Command(title=f"Attest {pretty}", command=ATTEST_COMMAND, arguments=[args]),
    )
