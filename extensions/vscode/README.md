# Ladex for VS Code

Flags AI components inline as you edit Python — inference APIs, models, agent frameworks,
vector stores — and nudges what each obligates under the EU AI Act. Nothing shows on non-AI
code (ruthless silence).

All detection runs in the Ladex Python engine, the *same* engine the CLI and PR check use —
the editor can never disagree with the gate.

## Install

**1. Install the Ladex engine** (the extension talks to it):

```bash
pip install ladex        # or:  uv tool install ladex  /  pipx install ladex
ladex --version          # verify it's on your PATH
```

**2. Install the extension** — either:

- **From a `.vsix`:** download `ladex-<version>.vsix` from the
  [Releases page](https://github.com/aibhuyan/ladex/releases), then in VS Code open the
  Extensions panel → `⋯` menu → **Install from VSIX…** (or run
  `code --install-extension ladex-<version>.vsix`).
- **From the Marketplace:** search **“Ladex”** in the Extensions panel *(once published)*.

Open any Python file that uses an AI library — diagnostics appear as you type.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `ladex.serverCommand` | `ladex` | Command that starts the engine. Set to a full path if `ladex` isn't on PATH. |
| `ladex.serverArgs` | `["serve"]` | Arguments passed to it. |

If you see *“could not start 'ladex serve'”*, the engine isn't on your PATH — install it
(step 1) or point `ladex.serverCommand` at the executable
(e.g. `.../.venv/Scripts/ladex.exe`).

## Development (contributing to the extension)

You only need this if you're hacking on the extension itself:

```bash
cd extensions/vscode
npm install
npm run compile      # or: npm run watch
```

Then press **F5** — the bundled launch config compiles, puts the repo's `.venv` on PATH, and
opens `demo/` in an Extension Development Host so you can see live diagnostics.

Build a distributable package with `npm run package` → `ladex-<version>.vsix`.
