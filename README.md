# Ladex

**A bill of lading for AI.**

You already require a bill of lading for physical cargo and an SBOM for software.
Ladex is the one for AI — it records what AI is aboard your codebase, from whom, and
under what terms, captured at the moment the code is written rather than discovered
after the fact.

Ladex is a shift-left AI governance tool for developers. When you write an AI-relevant
line of code — importing an agent framework, loading a Hugging Face model, calling an
inference API, provisioning a GPU node pool in Terraform — Ladex detects it and answers
three questions inline:

1. **What is this?** (model / dataset / agent framework / vector store / inference API)
2. **What does it obligate?** (EU AI Act Art. 50 disclosure, Art. 53 GPAI
   documentation, Annex III high-risk triggers)
3. **What's auto-verifiable vs. what needs a human?** CVEs and licenses resolve
   automatically. Training-data provenance and consent basis cannot be derived by any
   scanner — they are flagged `UNDOCUMENTED` and require a signed human attestation,
   never a fake green checkmark.

The output is a CycloneDX ML-BOM committed to the repo, diffable in PRs, with signed
attestations for the fields no tool can derive.

> Ladex records what's aboard; it does not block attacks.

## Status

Early development. See `CLAUDE.md` for scope, design rules, and the current build step.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12.

```bash
uv sync                 # create the environment
uv run ladex --version  # smoke test
uv run ruff check .
uv run mypy
uv run pytest
```

## License

MIT — see `LICENSE`.
