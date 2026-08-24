"""The built-in EU AI Act bundles load, validate, and are well-formed."""

from __future__ import annotations

import textwrap

import pytest

from ladex.engine.policy import PolicyError, load_builtin_bundles, parse_bundle
from ladex.engine.policy.models import Verification


def test_builtin_bundles_load() -> None:
    bundles = load_builtin_bundles()
    ids = {b.id for b in bundles}
    assert "eu-ai-act-art-50" in ids


def test_art50_rules_require_attestation() -> None:
    bundle = next(b for b in load_builtin_bundles() if b.id == "eu-ai-act-art-50")
    rule_ids = {r.id for r in bundle.rules}
    assert "art-50-1-ai-interaction-disclosure" in rule_ids
    # Transparency compliance can't be derived from code -> attestation.
    for rule in bundle.rules:
        assert rule.verification is Verification.REQUIRES_ATTESTATION


def test_unknown_project_key_rejected() -> None:
    text = textwrap.dedent(
        """
        schema_version: 1
        id: bad-bundle
        regulation: EU AI Act
        version: 0.1.0
        rules:
          - id: r1
            title: T
            citation: Art. X
            obligation: do a thing
            verification: derivable
            applies_when:
              project: {teleported: true}
        """
    )
    with pytest.raises(PolicyError, match="unknown project condition key"):
        parse_bundle(text, source="bad")


def test_unknown_verification_rejected() -> None:
    text = textwrap.dedent(
        """
        schema_version: 1
        id: bad
        regulation: EU AI Act
        version: 0.1.0
        rules:
          - id: r1
            title: T
            citation: Art. X
            obligation: do a thing
            verification: telepathy
            applies_when: {component_type: [model]}
        """
    )
    with pytest.raises(PolicyError):
        parse_bundle(text, source="bad")


def test_unsupported_schema_version_rejected() -> None:
    text = textwrap.dedent(
        """
        schema_version: 99
        id: b
        regulation: EU AI Act
        version: 0.1.0
        rules:
          - id: r1
            title: T
            citation: Art. X
            obligation: x
            verification: derivable
            applies_when: {}
        """
    )
    with pytest.raises(PolicyError, match="not supported"):
        parse_bundle(text, source="bad")
