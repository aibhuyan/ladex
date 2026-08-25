# Releasing Ladex

Two GitHub Actions workflows drive releases:

- **`ci.yml`** — runs `ruff`, `mypy`, and `pytest` on Linux, macOS, and Windows for every
  push to `main` and every PR.
- **`release.yml`** — on a version tag, builds per-OS single binaries + the wheel, publishes a
  GitHub Release with them attached, and pushes the wheel to PyPI.

## One-time setup (required before the first CI-driven PyPI publish)

The `pypi-publish` job uses **Trusted Publishing** (OIDC) — no API token stored in GitHub.
Configure it once:

1. **PyPI** → project **ladex** → *Manage* → *Publishing* → **Add a new pending/trusted
   publisher (GitHub)**:
   - Owner: `aibhuyan`
   - Repository: `ladex`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
2. **GitHub** → repo *Settings* → *Environments* → **New environment** named `pypi`
   (optionally add a required reviewer so publishes are gated).

> Prefer a token instead? Drop the `environment:`/`permissions: id-token` lines from the
> `pypi-publish` job, add a `PYPI_API_TOKEN` repo secret, and pass
> `password: ${{ secrets.PYPI_API_TOKEN }}` to the publish action.

## Cutting a release

```bash
# 1. Bump the version in three places:
#    pyproject.toml  ·  src/ladex/__init__.py  ·  tests/test_smoke.py (two asserts)
# 2. Commit, then tag and push:
git commit -am "Release v0.1.2"
git tag -a v0.1.2 -m "Ladex v0.1.2"
git push && git push origin v0.1.2
```

The tag push triggers `release.yml`, which:
1. builds `ladex-<ver>-{linux-x64,macos-arm64,windows-x64}` (smoke-tested),
2. builds per-platform VS Code extensions with the engine bundled
   (`ladex-<ver>-{win32-x64,darwin-arm64,linux-x64}.vsix`) + a universal fallback,
3. builds `ladex-<ver>-py3-none-any.whl` + sdist,
4. creates the **GitHub Release** with all of the above attached,
5. publishes the wheel to **PyPI** (trusted publishing),
6. publishes every VSIX to the **VS Code Marketplace** (needs the `VSCE_PAT` secret).

### Marketplace publishing setup (one-time)

Add a repo secret **`VSCE_PAT`** (Settings → Secrets and variables → Actions) — an Azure
DevOps Personal Access Token with **Marketplace: Manage** scope, **All accessible
organizations**. Without it, the `marketplace-publish` job no-ops (it won't fail the release).

> ⚠️ Azure DevOps is deprecating all-orgs PATs on **2026-12-01**. Before then, rotate to
> Entra ID auth (`vsce publish --azure-credential`) or the current replacement per the
> `@vscode/vsce` docs, and update the workflow accordingly.

## Backfilling binaries onto an existing release

Run the **release** workflow manually (Actions → release → *Run workflow*). It rebuilds the
binaries/wheel for the current `pyproject.toml` version and attaches them to that version's
GitHub Release **without** touching PyPI.

## Notes

- **macOS binaries are Apple-Silicon (arm64) only.** Intel-Mac (x64) runners queue for a
  long time on GitHub-hosted CI, so we don't build an Intel binary — Intel-Mac users install
  the universal wheel via `pip install ladex` instead.
- **macOS binaries are unsigned.** On first run users may need to right-click → Open, or
  `xattr -d com.apple.quarantine ladex-*-macos-*`. Signing needs an Apple Developer cert.
- **Linux binary** targets the runner's glibc (Ubuntu). Very old distros may need the wheel.
- PyPI versions are immutable — never re-tag a published version; always bump.
