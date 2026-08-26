<p align="center">
  <img src="https://raw.githubusercontent.com/aibhuyan/ladex/main/assets/ladex-social-card.png" alt="Ladex — a bill of lading for AI" width="640">
</p>

# Ladex for VS Code

Flags AI components inline as you edit Python — inference APIs, models, agent frameworks,
vector stores — and nudges what each obligates under the EU AI Act. Nothing shows on non-AI
code (ruthless silence).

All detection runs in the Ladex Python engine, the *same* engine the CLI and PR check use —
the editor can never disagree with the gate.

## Install

The platform builds **bundle the Ladex engine** — one install, no separate `pip install`.

- **From the Marketplace:** search **“Ladex”** in the Extensions panel (or open the
  [listing](https://marketplace.visualstudio.com/items?itemName=ladex.ladex)) — VS Code
  automatically installs the build for your OS/CPU.
- **From a `.vsix`:** download the one matching your platform from the
  [Releases page](https://github.com/aibhuyan/ladex/releases) —
  `ladex-<version>-{win32-x64,darwin-arm64,linux-x64}.vsix` — then Extensions panel → `⋯` →
  **Install from VSIX…** (or `code --install-extension <file>.vsix`).

Open any Python file that uses an AI library — diagnostics appear as you type. No engine setup.

> On a platform without a bundled build (e.g. Intel Mac, linux-arm64), install
> `ladex-<version>-universal.vsix` and provide the engine yourself: `pip install ladex`.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `ladex.serverCommand` | `ladex` | Overrides the engine command. Leave as `ladex` to use the bundled binary (falling back to a `ladex` on PATH); set a full path to force a specific engine. |
| `ladex.serverArgs` | `["serve"]` | Arguments passed to the engine command. |
| `ladex.diagnostics` | `actionable` | Editor noise floor. `actionable` underlines only what needs a human — a loadable model with unattested provenance/consent — and stays silent on ordinary AI imports/calls. `all` also shows the full inventory as faint hints. `off` disables diagnostics. Changing it restarts the engine automatically. |

The extension resolves the engine in this order: an explicit non-default `serverCommand` →
the **bundled binary** (`bin/ladex`) → a `ladex` on your PATH. If it can't start any, it shows
a message telling you to `pip install ladex` or set `ladex.serverCommand`.

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
