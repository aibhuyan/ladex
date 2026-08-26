"""The pygls language server wrapping the Ladex engine.

Thin by design: it owns document lifecycle, diagnostic publishing, and quick-fix code actions,
and delegates all detection to :mod:`diagnostics`. The VS Code extension is a thin client that
launches ``ladex serve``, points it at Python files, and turns the "attest" code action into a
`ladex attest` run.
"""

from __future__ import annotations

from pathlib import Path

from lsprotocol import types
from pygls.lsp.server import LanguageServer
from pygls.uris import to_fs_path

from ladex import __version__
from ladex.engine.detect import PythonDetector
from ladex.engine.server.diagnostics import (
    DEFAULT_MODE,
    DiagnosticsMode,
    build_diagnostics,
    code_actions,
)

SERVER_NAME = "ladex-lsp"


def create_server(mode: DiagnosticsMode = DEFAULT_MODE) -> LanguageServer:
    """Build a configured Ladex language server (not yet started).

    ``mode`` sets the editor noise floor (see :data:`DiagnosticsMode`); the VS Code client
    passes it from the ``ladex.diagnostics`` setting via ``ladex serve --diagnostics``.
    """
    server = LanguageServer(SERVER_NAME, __version__)
    # One detector for the server's lifetime — the taxonomy is loaded once.
    detector = PythonDetector()

    def _root(ls: LanguageServer) -> Path | None:
        uri = ls.workspace.root_uri
        if not uri:
            return None
        fs = to_fs_path(uri)
        return Path(fs) if fs else None

    def _publish(ls: LanguageServer, uri: str, text: str) -> None:
        diagnostics = build_diagnostics(text, detector, _root(ls), mode)
        ls.text_document_publish_diagnostics(
            types.PublishDiagnosticsParams(uri=uri, diagnostics=diagnostics)
        )

    @server.feature(types.TEXT_DOCUMENT_DID_OPEN)
    def did_open(ls: LanguageServer, params: types.DidOpenTextDocumentParams) -> None:
        _publish(ls, params.text_document.uri, params.text_document.text)

    @server.feature(types.TEXT_DOCUMENT_DID_CHANGE)
    def did_change(ls: LanguageServer, params: types.DidChangeTextDocumentParams) -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _publish(ls, params.text_document.uri, doc.source)

    @server.feature(types.TEXT_DOCUMENT_DID_SAVE)
    def did_save(ls: LanguageServer, params: types.DidSaveTextDocumentParams) -> None:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        _publish(ls, params.text_document.uri, doc.source)

    @server.feature(types.TEXT_DOCUMENT_CODE_ACTION)
    def code_action(ls: LanguageServer, params: types.CodeActionParams) -> list[types.CodeAction]:
        doc = ls.workspace.get_text_document(params.text_document.uri)
        return code_actions(doc.source, params.text_document.uri, params.range, _root(ls), detector)

    return server


def start_stdio(mode: DiagnosticsMode = DEFAULT_MODE) -> None:
    """Run the server over stdio (how the VS Code client launches it)."""
    create_server(mode).start_io()
