"""Server: the pygls LSP server wrapping the engine for IDE surfaces."""

from __future__ import annotations

from ladex.engine.server.diagnostics import build_diagnostics
from ladex.engine.server.server import SERVER_NAME, create_server, start_stdio

__all__ = ["SERVER_NAME", "build_diagnostics", "create_server", "start_stdio"]
