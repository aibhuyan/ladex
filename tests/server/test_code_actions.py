"""LSP code actions + attestation-aware diagnostics."""

from __future__ import annotations

import textwrap
from pathlib import Path

from lsprotocol import types

from ladex.engine.attest import (
    AttestationStore,
    LocalSigner,
    create_attestation,
)
from ladex.engine.server import build_diagnostics, code_actions, create_server
from ladex.engine.server.diagnostics import ATTEST_COMMAND

MODEL = "sentence-transformers/all-MiniLM-L6-v2"
FULL = types.Range(
    start=types.Position(line=0, character=0),
    end=types.Position(line=50, character=0),
)


def _src() -> str:
    return textwrap.dedent(f'EMBED = "{MODEL}"\nimport openai\nMODEL = "gpt-4o"\n')


def test_code_action_offered_for_loadable_model() -> None:
    actions = code_actions(_src(), "file:///x.py", FULL)
    titles = [a.title for a in actions]
    assert any("attest provenance" in t and MODEL in t for t in titles)
    assert any("attest consent basis" in t for t in titles)


def test_code_action_carries_the_attest_command() -> None:
    action = next(a for a in code_actions(_src(), "file:///x.py", FULL) if "provenance" in a.title)
    assert action.command is not None
    assert action.command.command == ATTEST_COMMAND
    assert action.command.arguments is not None
    arg = action.command.arguments[0]
    assert isinstance(arg, dict)
    assert arg["subject"] == MODEL
    assert arg["claim"] == "provenance"


def test_no_action_for_hosted_model_name() -> None:
    # gpt-4o is a hosted-API name, not loadable weights -> no attest quick-fix.
    actions = code_actions('M = "gpt-4o"', "file:///x.py", FULL)
    assert actions == []


def test_attestation_removes_the_action(tmp_path: Path) -> None:
    signer = LocalSigner(key_path=tmp_path / "key")
    store = AttestationStore.for_root(tmp_path)
    for claim in ("provenance", "consent_basis"):
        store.add(create_attestation(MODEL, claim, "public data", "me@org", signer))
    actions = code_actions(_src(), "file:///x.py", FULL, root=tmp_path)
    assert actions == []  # both claims attested -> nothing left to fix


def test_unattested_model_surfaces_with_attestation_ask(tmp_path: Path) -> None:
    # Default mode: the unattested loadable model is the one thing that speaks up.
    unattested = build_diagnostics(_src())
    model_diag = next(d for d in unattested if d.code == "huggingface.sentence-transformers-id")
    assert "need attestation" in model_diag.message


def test_attestation_silences_the_model_in_default_mode(tmp_path: Path) -> None:
    signer = LocalSigner(key_path=tmp_path / "key")
    store = AttestationStore.for_root(tmp_path)
    for claim in ("provenance", "consent_basis"):
        store.add(create_attestation(MODEL, claim, "public data", "me@org", signer))

    # Once signed, there's nothing left to act on -> the squiggle disappears (default mode).
    attested = build_diagnostics(_src(), root=tmp_path)
    assert not any(d.code == "huggingface.sentence-transformers-id" for d in attested)

    # In 'all' mode it's still inventory, now confirmed as attested.
    shown = build_diagnostics(_src(), root=tmp_path, mode="all")
    model_diag = next(d for d in shown if d.code == "huggingface.sentence-transformers-id")
    assert "attested" in model_diag.message
    assert model_diag.severity is types.DiagnosticSeverity.Hint


def test_selection_narrows_actions() -> None:
    # A selection on the openai line (line 1) should not offer the model action (line 0).
    line1 = types.Range(
        start=types.Position(line=1, character=0),
        end=types.Position(line=1, character=5),
    )
    assert code_actions(_src(), "file:///x.py", line1) == []


def test_server_advertises_code_action() -> None:
    server = create_server()
    assert server is not None  # smoke: feature registration didn't raise
