<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/aibhuyan/ladex/main/assets/ladex-lockup-dark.png">
    <img src="https://raw.githubusercontent.com/aibhuyan/ladex/main/assets/ladex-lockup-light.png" alt="Ladex" width="360">
  </picture>
</p>

<p align="center"><strong>A bill of lading for AI.</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.2-3b82f6?style=flat" alt="version 0.1.2">
  <img src="https://img.shields.io/github/actions/workflow/status/aibhuyan/ladex/ci.yml?branch=main&style=flat&label=ci" alt="CI status">
  <img src="https://img.shields.io/github/stars/aibhuyan/ladex?style=flat&color=3b82f6" alt="GitHub stars">
  <img src="https://img.shields.io/badge/license-MIT-3b82f6?style=flat" alt="license MIT">
  <img src="https://img.shields.io/badge/python-3.12+-3b82f6?style=flat" alt="python 3.12+">
  <img src="https://img.shields.io/badge/tests-139%20passing-22c55e?style=flat" alt="tests 139 passing">
  <img src="https://img.shields.io/badge/output-CycloneDX%20ML--BOM-3b82f6?style=flat" alt="CycloneDX ML-BOM">
  <img src="https://img.shields.io/badge/EU%20AI%20Act-Art.%2050-3b82f6?style=flat" alt="EU AI Act Art. 50">
</p>

---

You already require a **bill of lading** for physical cargo and an **SBOM** for software.
Ladex is the one for **AI** — it records what AI is aboard your codebase, from whom, and under
what terms, captured at the moment the code is written rather than discovered after the fact.

Ladex is a shift-left AI governance tool for developers. When you write an AI-relevant line of
code — importing an agent framework, loading a Hugging Face model, calling an inference API,
provisioning a GPU node pool in Terraform — Ladex detects it and answers three questions:

1. **What is this?** &nbsp;model / dataset / agent framework / vector store / inference API
2. **What does it obligate?** &nbsp;EU AI Act Art. 50 disclosure, Annex III high-risk triggers
3. **What's auto-verifiable vs. what needs a human?** &nbsp;CVEs and licenses resolve
   automatically. Training-data provenance and consent basis can't be derived by any scanner —
   they're flagged `UNDOCUMENTED` and require a **signed human attestation**, never a fake green
   checkmark.

The output is a **CycloneDX ML-BOM** committed to your repo, diffable in PRs, with signed
attestations for the fields no tool can derive.

> Ladex records what's aboard; it does not block attacks.

## What it does

```
detect (Python + Terraform + Kubernetes)
  → enrich    PyPI licenses · OSV CVEs · Hugging Face model cards   (cached, offline-capable)
  → obligate  EU AI Act Art. 50 — applies / may-apply / silent; derivable vs. attestation
  → BOM       deterministic CycloneDX ML-BOM that diffs cleanly in PRs
  → attest    in-toto/DSSE signature fills an UNDOCUMENTED gap with a verifiable declaration

surfaces:  CLI   +   VS Code (LSP, inline diagnostics as you type)   — one shared engine
```

## Install

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
git clone https://github.com/aibhuyan/ladex
cd ladex
uv sync
uv run ladex --version
```

## Quickstart

```bash
# See every AI component in a repo (silent on non-AI code)
uv run ladex scan path/to/repo

# Add real facts: licenses, CVEs, model cards (cached; --offline works from cache)
uv run ladex scan path/to/repo --enrich

# What does it obligate under the EU AI Act? (declare project facts to resolve "may apply")
uv run ladex policy check path/to/repo --user-facing

# Produce the committable, deterministic ML-BOM
uv run ladex scan path/to/repo --write-bom aibom.cdx.json

# Sign a human answer for a gap no scanner can fill, then verify it
uv run ladex attest "sentence-transformers/all-MiniLM-L6-v2" \
    --claim provenance --value "Curated public corpora, reviewed 2026-08"
uv run ladex verify
```

### Example

```
app.py
   7:10  inference_api    openai.client       openai.OpenAI (OpenAI)
  12:9   model            openai.model-id     gpt-4o (OpenAI)

infra/main.tf
  20:1   vector_store     iac.tf.vector-store-unencrypted   HIGH   aws_opensearch_domain.vectors
                                                                   - Vector store is not encrypted at rest

Summary: 3 detection(s) across 2 of 2 file(s) scanned.
```

## In your editor

The VS Code extension is a thin client over the same engine — inline diagnostics as you type,
nothing on non-AI code. Install it, no repo checkout needed:

1. Install the engine so the extension can call it: `pip install ladex` (or `uv tool install ladex`).
2. Grab `ladex-<version>.vsix` from the [Releases page](https://github.com/aibhuyan/ladex/releases)
   → Extensions panel → **Install from VSIX…** (Marketplace listing coming soon).

Then open any Python file that uses an AI library. See
[`extensions/vscode/README.md`](extensions/vscode/README.md) for configuration and development.

## Design principles

- **One engine, three surfaces.** The IDE, CLI, and (v2) PR check all call the same Python
  engine — the editor can never disagree with the gate.
- **Ruthless silence.** If a line isn't AI-relevant, Ladex says nothing.
- **Honest gaps.** `UNDOCUMENTED` is a valid, valuable output. A green checkmark only appears
  when something was actually verified — or signed by a named human.
- **Policy as versioned data.** Taxonomy and EU AI Act rules are updatable bundles, not code.

## Scope (v1)

**Python + Terraform + Kubernetes detection. EU AI Act. Two surfaces (CLI + VS Code).**
The GitHub PR check and evidence graph are v2.

## Development

```bash
uv run ruff check .
uv run mypy
uv run pytest
```

Pre-commit (`ruff` + `mypy`) runs on every commit; run `uv run pre-commit install` once.

## License

MIT — see [`LICENSE`](LICENSE).
