"""LSP diagnostics mapping: ranges, severity, the noise-floor modes, and engine reuse."""

from __future__ import annotations

import textwrap

from lsprotocol import types

from ladex.engine.server import build_diagnostics, create_server

# A loadable Hugging Face model (org/name) with no attestation: the one "actionable" case —
# a human still has to sign its provenance/consent. Everything else is inventory.
ACTIONABLE_MODEL = 'M = "sentence-transformers/all-MiniLM-L6-v2"'


def _all(code: str) -> list[types.Diagnostic]:
    """Every detection surfaced (inventory + actionable), the way `mode='all'` shows it."""
    return build_diagnostics(textwrap.dedent(code), mode="all")


def _default(code: str) -> list[types.Diagnostic]:
    """Default noise floor: only actionable items."""
    return build_diagnostics(textwrap.dedent(code))


# -- default (actionable) mode: ruthless silence in the editor -----------------


def test_plain_import_is_silent_by_default() -> None:
    # A bare AI import carries no unmet obligation -> nothing to act on -> no squiggle.
    assert _default("import openai") == []


def test_hosted_model_string_is_silent_by_default() -> None:
    # "gpt-4o" is a hosted API model, not a loadable repo id -> not attestable -> silent.
    assert _default('MODEL = "gpt-4o"') == []


def test_actionable_model_surfaces_by_default() -> None:
    diags = _default(ACTIONABLE_MODEL)
    assert len(diags) == 1
    d = diags[0]
    assert d.severity is types.DiagnosticSeverity.Information  # actionable, carries the quick-fix
    assert d.source == "ladex"
    assert "attestation" in d.message.lower()


def test_noise_is_silent() -> None:
    assert _default("import os\nx = 1\n") == []


# -- all mode: full inventory, demoted to hints --------------------------------


def test_all_mode_shows_inventory_as_hint() -> None:
    diags = _all("import openai")
    assert len(diags) == 1
    d = diags[0]
    assert d.severity is types.DiagnosticSeverity.Hint  # inventory: faint, out of Problems noise
    assert d.code == "openai.import"


def test_all_mode_keeps_actionable_at_information() -> None:
    info = types.DiagnosticSeverity.Information
    d = next(d for d in _all(ACTIONABLE_MODEL) if d.severity is info)
    assert "attestation" in d.message.lower()


def test_message_names_provider_and_type() -> None:
    diags = _all("import openai\nopenai.OpenAI()")
    call = next(d for d in diags if d.code == "openai.client")
    assert "OpenAI" in call.message
    assert "inference_api" in call.message


# -- dedupe --------------------------------------------------------------------


def test_repeats_collapse_to_first_occurrence() -> None:
    code = f"{ACTIONABLE_MODEL}\n{ACTIONABLE_MODEL}\n{ACTIONABLE_MODEL}"
    diags = _default(code)
    assert len(diags) == 1  # attesting once resolves every use; one squiggle is enough
    assert diags[0].range.start.line == 0  # the first occurrence is the one kept


# -- off mode ------------------------------------------------------------------


def test_off_mode_disables_everything() -> None:
    assert build_diagnostics(ACTIONABLE_MODEL, mode="off") == []


# -- ranges & robustness -------------------------------------------------------


def test_ranges_are_zero_based_for_lsp() -> None:
    # Detection spans are 1-based lines; LSP wants 0-based. Line 3 -> range.start.line == 2.
    diags = build_diagnostics("\n\nimport openai", mode="all")
    imp = next(d for d in diags if d.code == "openai.import")
    assert imp.range.start.line == 2


def test_invalid_syntax_still_yields_diagnostics() -> None:
    diags = build_diagnostics("import openai\ndef broken(:\n    openai.OpenAI(", mode="all")
    assert any(d.code == "openai.import" for d in diags)


def test_create_server_smoke() -> None:
    assert create_server() is not None
    assert create_server("all") is not None
