# Ladex GitHub Action

The third Ladex surface: run the **same engine** on pull requests. It detects AI components,
records EU AI Act obligations, and **gates the check** on undocumented provenance — posting a
sticky PR comment, inline annotations, and a job summary.

> One engine, three surfaces — the PR gate can never disagree with the CLI or the editor.

## Usage

Add `.github/workflows/ladex.yml` (see `example-workflow.yml`):

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  ladex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: aibhuyan/ladex/apps/github@v0.2.2
        with:
          fail-on: gaps          # none | gaps | strict
          # user-facing: "true"  # declare project facts for Art. 50
          comment: "true"
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Path to scan. |
| `fail-on` | `gaps` | `none` (report only) · `gaps` (fail on unattested provenance + applicable attestation obligations) · `strict` (also fail when obligations *may* apply). |
| `user-facing` | `""` | `true` / `false` / `""` — declares whether the system interacts with people (EU AI Act Art. 50(1)). |
| `synthetic-content` | `""` | `true` / `false` / `""` — declares whether it generates synthetic content (Art. 50(2)). |
| `comment` | `true` | Post/update a sticky PR comment with the report. |
| `ladex-version` | `""` | Pin a version (e.g. `0.1.3`); empty installs the latest from PyPI. |
| `diff` | `true` | On PRs, report which AI components this change adds/removes vs the base branch. |

## What it does

1. `pip install ladex` and runs `ladex ci --format github` — inline **annotations** on the AI
   lines and a **job summary**.
2. Upserts a **sticky PR comment**: components found, obligations, and the exact
   `ladex attest …` commands to close each documentation gap.
3. **Fails the check** per `fail-on`, so a PR that adds a model with UNDOCUMENTED provenance
   can't merge until a human attests it.

## Resolving a gap

When the check flags an undocumented model, a maintainer records the signed answer and commits
`.ladex/attestations.json`:

```bash
ladex attest "org/model" --claim provenance --value "Curated public corpora, reviewed 2026-08" --attester you@org
```

On the next push the gap clears and the check passes.
