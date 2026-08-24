"""LSP diagnostics mapping: ranges, severity, silence, and engine reuse."""

from __future__ import annotations

import textwrap

from lsprotocol import types

from ladex.engine.server import build_diagnostics, create_server


def _diags(code: str) -> list[types.Diagnostic]:
    return build_diagnostics(textwrap.dedent(code))


def test_import_produces_one_information_diagnostic() -> None:
    diags = _diags("import openai")
    assert len(diags) == 1
    d = diags[0]
    assert d.severity is types.DiagnosticSeverity.Information  # informational, never an error
    assert d.source == "ladex"
    assert d.code == "openai.import"


def test_ranges_are_zero_based_for_lsp() -> None:
    # Detection spans are 1-based lines; LSP wants 0-based. Line 3 -> range.start.line == 2.
    diags = build_diagnostics("\n\nimport openai")
    imp = next(d for d in diags if d.code == "openai.import")
    assert imp.range.start.line == 2


def test_noise_is_silent() -> None:
    assert _diags("import os\nx = 1\n") == []


def test_model_string_message_mentions_attestation() -> None:
    diags = _diags('MODEL = "gpt-4o"')
    model = next(d for d in diags if d.code == "openai.model-id")
    assert "attestation" in model.message.lower()


def test_message_names_provider_and_type() -> None:
    diags = _diags("import openai\nopenai.OpenAI()")
    call = next(d for d in diags if d.code == "openai.client")
    assert "OpenAI" in call.message
    assert "inference_api" in call.message


def test_invalid_syntax_still_yields_diagnostics() -> None:
    diags = build_diagnostics("import openai\ndef broken(:\n    openai.OpenAI(")
    assert any(d.code == "openai.import" for d in diags)


def test_create_server_smoke() -> None:
    server = create_server()
    assert server is not None
