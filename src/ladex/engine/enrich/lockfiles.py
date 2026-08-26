"""Resolve the *actual* pinned version of a dependency from a project's lockfiles.

Enrichment must describe what a project really ships, not PyPI's latest release — otherwise
CVE results (from OSV) apply to the wrong version. This reads the common Python lockfiles and
returns ``normalized name -> (version, source_file)``. It's best-effort and error-tolerant:
an unreadable/exotic lockfile is skipped, not fatal.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path

# PEP 503 normalization: lowercase, runs of -, _, . collapse to a single -.
_NORM_RE = re.compile(r"[-_.]+")
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")


def normalize(name: str) -> str:
    return _NORM_RE.sub("-", name).lower()


def resolve_versions(root: Path) -> dict[str, tuple[str, str]]:
    """Map each locked distribution (normalized name) to ``(version, source_file)``.

    Priority: uv.lock > poetry.lock > Pipfile.lock > requirements.txt. The first source that
    pins a package wins.
    """
    resolved: dict[str, tuple[str, str]] = {}
    sources: list[tuple[str, Iterator[tuple[str, str]]]] = [
        ("uv.lock", _from_toml_packages(root / "uv.lock")),
        ("poetry.lock", _from_toml_packages(root / "poetry.lock")),
        ("Pipfile.lock", _from_pipfile_lock(root / "Pipfile.lock")),
        ("requirements.txt", _from_requirements(root / "requirements.txt")),
    ]
    for source, pairs in sources:
        for name, version in pairs:
            resolved.setdefault(normalize(name), (version, source))
    return resolved


def _from_toml_packages(path: Path) -> Iterator[tuple[str, str]]:
    """uv.lock and poetry.lock both use ``[[package]]`` tables with name + version."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return
    for pkg in data.get("package", []) or []:
        if isinstance(pkg, dict) and "name" in pkg and "version" in pkg:
            yield str(pkg["name"]), str(pkg["version"])


def _from_pipfile_lock(path: Path) -> Iterator[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    for section in ("default", "develop"):
        for name, spec in (data.get(section) or {}).items():
            version = spec.get("version") if isinstance(spec, dict) else None
            if isinstance(version, str) and version.startswith("=="):
                yield str(name), version[2:]


def _from_requirements(path: Path) -> Iterator[tuple[str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        match = _REQ_RE.match(line)
        if match:
            yield match.group(1), match.group(2)
