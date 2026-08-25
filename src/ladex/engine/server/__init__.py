"""Server: the pygls LSP server wrapping the engine for IDE surfaces."""

from __future__ import annotations

from ladex.engine.server.diagnostics import ATTEST_COMMAND, build_diagnostics, code_actions
from ladex.engine.server.server import SERVER_NAME, create_server, start_stdio

__all__ = [
    "ATTEST_COMMAND",
    "SERVER_NAME",
    "build_diagnostics",
    "code_actions",
    "create_server",
    "start_stdio",
]
