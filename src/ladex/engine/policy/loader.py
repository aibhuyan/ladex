"""Load and validate policy bundles from the wheel or the filesystem.

Strict, like the taxonomy loader: a malformed bundle raises :class:`PolicyError` with a
pointed message rather than silently evaluating fewer rules. Built-in bundles ship under
``ladex.packs.policy`` and are read via :mod:`importlib.resources`.
"""

from __future__ import annotations

from collections.abc import Iterator
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

import yaml
from pydantic import ValidationError

from ladex.engine.policy.models import CURRENT_POLICY_SCHEMA_VERSION, PolicyBundle

_BUILTIN_ANCHOR = "ladex.packs"
_BUILTIN_DIR = "policy"


class PolicyError(Exception):
    """Raised when a policy bundle cannot be loaded or fails validation."""


def parse_bundle(text: str, *, source: str) -> PolicyBundle:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: top level must be a mapping, got {type(raw).__name__}")
    try:
        bundle = PolicyBundle.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(f"{source}: {_format_error(exc)}") from exc
    if bundle.schema_version != CURRENT_POLICY_SCHEMA_VERSION:
        raise PolicyError(
            f"{source}: schema_version {bundle.schema_version} is not supported "
            f"(this build understands version {CURRENT_POLICY_SCHEMA_VERSION})"
        )
    return bundle


def load_bundle_file(path: Path) -> PolicyBundle:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy bundle {path}: {exc}") from exc
    return parse_bundle(text, source=str(path))


def _builtin_bundle_resources() -> Iterator[Traversable]:
    root = resources.files(_BUILTIN_ANCHOR).joinpath(_BUILTIN_DIR)
    if not root.is_dir():
        return
    # Bundles may be nested under a regulation directory (eu_ai_act/*.yaml).
    yield from _walk_yaml(root)


def _walk_yaml(node: Traversable) -> Iterator[Traversable]:
    for entry in sorted(node.iterdir(), key=lambda e: e.name):
        if entry.is_dir():
            yield from _walk_yaml(entry)
        elif entry.name.endswith(".yaml") and entry.is_file():
            yield entry


def load_builtin_bundles() -> list[PolicyBundle]:
    bundles: list[PolicyBundle] = []
    seen: dict[str, str] = {}
    for res in _builtin_bundle_resources():
        bundle = parse_bundle(res.read_text(encoding="utf-8"), source=res.name)
        if bundle.id in seen:
            raise PolicyError(
                f"duplicate bundle id {bundle.id!r} in {res.name}; "
                f"first seen in {seen[bundle.id]}"
            )
        seen[bundle.id] = res.name
        bundles.append(bundle)
    return bundles


def _format_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)
