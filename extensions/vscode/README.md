# Ladex for VS Code

A thin client for the Ladex engine. As you edit Python, it flags AI components inline —
inference APIs, models, agent frameworks, vector stores — and nudges what each obligates
under the EU AI Act. It shows nothing on non-AI code (ruthless silence).

All detection runs in the Python engine (`ladex serve`), the *same* engine the CLI and PR
check use — the editor can never disagree with the gate.

## Requirements

- The **ladex** CLI on your PATH (`pip install ladex` / `uv tool install ladex`). Verify
  with `ladex serve --help`.
- VS Code ≥ 1.85.

## Build (from source)

```bash
cd extensions/vscode
npm install
npm run compile      # tsc -> out/extension.js
```

Then press **F5** in VS Code to launch an Extension Development Host, open a Python file
that imports an AI library, and watch the inline diagnostics appear.

## Settings

- `ladex.serverCommand` (default `ladex`) — the engine command.
- `ladex.serverArgs` (default `["serve"]`) — arguments to start the LSP server.
