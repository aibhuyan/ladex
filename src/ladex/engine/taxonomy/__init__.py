"""Taxonomy: versioned YAML rules mapping code signals to AI component types (★ IP)."""

from __future__ import annotations

from ladex.engine.taxonomy.loader import (
    Taxonomy,
    TaxonomyError,
    aggregate,
    load_builtin_packs,
    load_builtin_taxonomy,
    load_pack_file,
    load_project_taxonomy,
    load_user_taxonomy_packs,
    parse_pack,
)
from ladex.engine.taxonomy.models import (
    CURRENT_SCHEMA_VERSION,
    AttributeMatch,
    CallMatch,
    ComponentType,
    ImportMatch,
    Rule,
    StringMatch,
    TaxonomyPack,
)

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "AttributeMatch",
    "CallMatch",
    "ComponentType",
    "ImportMatch",
    "Rule",
    "StringMatch",
    "Taxonomy",
    "TaxonomyError",
    "TaxonomyPack",
    "aggregate",
    "load_builtin_packs",
    "load_builtin_taxonomy",
    "load_pack_file",
    "load_project_taxonomy",
    "load_user_taxonomy_packs",
    "parse_pack",
]
