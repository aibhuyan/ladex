"""Load, validate, and aggregate taxonomy packs.

The loader is deliberately strict: a malformed pack raises :class:`TaxonomyError` with a
pointed message rather than silently loading fewer rules. Built-in packs ship inside the
wheel under ``ladex.packs.taxonomy`` and are read via :mod:`importlib.resources`, so the
same code path works from an editable checkout and from an installed wheel.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

import yaml
from pydantic import ValidationError

from ladex.engine.taxonomy.models import (
    CURRENT_SCHEMA_VERSION,
    Rule,
    TaxonomyPack,
)

_BUILTIN_ANCHOR = "ladex.packs"
_BUILTIN_DIR = "taxonomy"


class TaxonomyError(Exception):
    """Raised when a taxonomy pack cannot be loaded or fails validation."""


def parse_pack(text: str, *, source: str) -> TaxonomyPack:
    """Parse and validate a single pack from YAML ``text``.

    ``source`` is used only for error messages (a file name or resource name).
    """
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TaxonomyError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise TaxonomyError(f"{source}: top level must be a mapping, got {type(raw).__name__}")
    try:
        pack = TaxonomyPack.model_validate(raw)
    except ValidationError as exc:
        raise TaxonomyError(f"{source}: {_format_validation_error(exc)}") from exc
    if pack.schema_version != CURRENT_SCHEMA_VERSION:
        raise TaxonomyError(
            f"{source}: schema_version {pack.schema_version} is not supported "
            f"(this build understands version {CURRENT_SCHEMA_VERSION})"
        )
    return pack


def load_pack_file(path: Path) -> TaxonomyPack:
    """Load and validate a pack from a filesystem ``path``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TaxonomyError(f"cannot read taxonomy pack {path}: {exc}") from exc
    return parse_pack(text, source=str(path))


def _builtin_pack_resources() -> Iterator[Traversable]:
    root = resources.files(_BUILTIN_ANCHOR).joinpath(_BUILTIN_DIR)
    if not root.is_dir():
        return
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yaml") and entry.is_file():
            yield entry


def load_builtin_packs() -> list[TaxonomyPack]:
    """Load every built-in pack shipped inside the wheel."""
    packs: list[TaxonomyPack] = []
    for res in _builtin_pack_resources():
        packs.append(parse_pack(res.read_text(encoding="utf-8"), source=res.name))
    return packs


@dataclass(frozen=True)
class Taxonomy:
    """An aggregate view over one or more packs with cross-pack invariants enforced."""

    packs: tuple[TaxonomyPack, ...]

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(rule for pack in self.packs for rule in pack.rules)

    def by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def __len__(self) -> int:
        return sum(len(pack.rules) for pack in self.packs)


def aggregate(packs: Iterable[TaxonomyPack]) -> Taxonomy:
    """Combine packs into a :class:`Taxonomy`, rejecting duplicate rule ids across packs."""
    materialized = tuple(packs)
    seen: dict[str, str] = {}
    for pack in materialized:
        for rule in pack.rules:
            if rule.id in seen:
                raise TaxonomyError(
                    f"duplicate rule id {rule.id!r} in pack {pack.name!r}; "
                    f"first seen in pack {seen[rule.id]!r}"
                )
            seen[rule.id] = pack.name
    return Taxonomy(packs=materialized)


def load_builtin_taxonomy() -> Taxonomy:
    """Load and aggregate all built-in packs into a validated :class:`Taxonomy`."""
    return aggregate(load_builtin_packs())


def _format_validation_error(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)
