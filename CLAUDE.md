# Ladex — Project Context

**Name origin:** _Ladex_ comes from **bill of lading** — the shipping document that
legally declares exactly what cargo is aboard, from whom, and under what terms. That is
the product thesis in one word. On-theme naming for modules, CLI verbs, and user-facing
strings: **manifest, declare, attest, consign, cargo**. Off-theme (never use):
**shield, guard, protect, defend**. Ladex records what's aboard; it doesn't block attacks.

- Python package: `ladex` · CLI: `ladex` · Domain: `ladex.dev`

## What Ladex is

A shift-left AI governance tool for developers. When a developer writes an AI-relevant
line of code — importing an agent framework, loading a Hugging Face model, calling an
inference API, provisioning a GPU node pool in Terraform — Ladex detects it in real time
and answers three questions inline:

1. **What is this?** (model / dataset / agent framework / vector store / inference API)
2. **What does it obligate?** (EU AI Act Art. 50 disclosure, Art. 53 GPAI
   documentation, Annex III high-risk triggers)
3. **What's auto-verifiable vs. what needs a human?** CVEs and licenses resolve
   automatically. Training-data provenance and consent basis cannot be derived by any
   scanner — they get flagged as `UNDOCUMENTED` → requires attestation, never a fake
   green checkmark.

The output artifact is a CycloneDX ML-BOM committed to the repo, diffable in PRs, with
signed human attestations for the fields no tool can derive. That artifact — provenance
captured at creation time — is the entire differentiation versus post-hoc discovery
scanners.

## Non-negotiable design rules

- **One engine, three surfaces.** IDE (via LSP), CLI, and GitHub PR check all call the
  same Python engine. Never fork detection logic across surfaces — drift between what
  the editor says and what the PR gate says destroys trust instantly.
- **Ruthless silence.** If a line isn't AI-relevant, Ladex outputs nothing. Zero noise.
  A false positive rate that annoys developers kills this product in week two.
- **Wrap, don't rebuild.** Never write a CVE matcher, a dependency resolver, or an IaC
  scanner. Those are commodity and free.
- **Honest gaps.** Never emit a green checkmark for something that wasn't actually
  verified. `UNDOCUMENTED` is a valid, valuable output.
- **Policy as versioned data, not code.** Regulations change (the EU AI Act shifted
  high-risk deadlines to Dec 2027). Policy bundles must be updatable without shipping a
  new binary.

## Tools to use under the hood

| Layer            | Tool                          | Notes                                                              |
| ---------------- | ----------------------------- | ----------------------------------------------------------------- |
| Code parsing     | py-tree-sitter                | Incremental + error-tolerant; parses half-typed code. `ast` can't.|
| Dependency graph | syft (shell out)              | Full transitive deps as CycloneDX. Don't hand-roll resolution.    |
| CVE data         | OSV.dev API, deps.dev         | Free, no lock-in. Cache aggressively.                             |
| Model metadata   | Hugging Face Hub API          | Model cards, license, base model.                                |
| AIBOM baseline   | OWASP AIBOM Generator         | model-card → CycloneDX with a completeness score.                |
| Model provenance | Cisco Model Provenance Kit    | Weight-level lineage. Wrap it.                                    |
| Policy engine    | OPA / Rego (embedded)         | Ship policy as versioned bundles.                                |
| IaC scanning     | Checkov (custom) + Trivy      | Checkov is Python — same process, clean custom-policy API.        |
| BOM output       | cyclonedx-python-lib, BomCTL  | Spec-compliant; CycloneDX ↔ SPDX translation.                    |
| Attestation      | Sigstore/cosign keyless + in-toto | Tamper-evident, no key management on day one.                 |
| IDE protocol     | pygls (LSP)                   | VS Code extension is a thin client; Neovim/JetBrains later free.  |
| Packaging        | uv, PyInstaller               | Single binary for CI.                                             |

If a tool choice turns out wrong once actually tried, say so and propose the
alternative. Do not silently substitute.

## v1 scope — resist all expansion

**Python only. EU AI Act only. Two surfaces (CLI + VS Code).** Postgres and the evidence
graph are v2 — do not build them now. If you find yourself designing a database schema in
v1, stop.

## Target structure

```
ladex/
├── engine/
│   ├── detect/      # ast_walker.py, manifests.py, iac.py
│   ├── taxonomy/    # ★ IP: frameworks/model_loaders/inference_apis/vector_stores .yaml
│   ├── enrich/      # osv.py, pypi.py, hfhub.py  (all cached)
│   ├── policy/      # ★ IP: eu_ai_act/*.rego
│   ├── bom/         # cyclonedx.py, spdx.py
│   ├── attest/      # sigstore signing of human attestations
│   └── server/      # LSP server
├── cli/             # `ladex scan`
├── extensions/vscode/
├── apps/github/     # v2
└── packs/           # distributable taxonomy + policy bundles
```

Implemented under `src/ladex/` (src layout). `packs/` ships inside the wheel via
`src/ladex/packs/`.

## Current status / next step

**Step 0 complete (pending user verification):** repo skeleton — `pyproject.toml` (uv),
`.gitignore`, README, CLAUDE.md, MIT license, pre-commit (ruff + mypy), src-layout package
with a trivial `ladex` CLI entrypoint that prints the version.

**Next: Step 1 — taxonomy schema + first ~20 rules** (langchain, openai, anthropic,
huggingface_hub, transformers, pinecone) with a schema validator and tests.
