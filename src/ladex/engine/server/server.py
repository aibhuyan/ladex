"""The pygls language server wrapping the Ladex engine.

Thin by design: it owns document lifecycle and diagnostic publishing, and delegates all
detection to :func:`build_diagnostics`. The VS Code extension is a thin client that just
launches ``ladex serve`` and points it at Python files.
"""

from __future__ import annotations

from lsprotocol import types
from pygls.lsp.server import LanguageServer

from ladex import __version__
from ladex.engine.detect import PythonDetector
from ladex.engine.server.diagnostics import build_diagnostics

SERVER_NAME = "ladex-lsp"


def create_server() -> LanguageServer:
    """Build a configured Ladex language server (not yet started)."""
    server = LanguageServer(SERVER_NAME, __version__)
    # One detector for the server's lifetime — the taxonomy is loaded once.
    detector = PythonDetector()

    def _publish(ls: LanguageServer, uri: str, text: str) -> None:
        diagnostics = build_diagnostics(text, detector)
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

    return server


def start_stdio() -> None:
    """Run the server over stdio (how the VS Code client launches it)."""
    create_server().start_io()
