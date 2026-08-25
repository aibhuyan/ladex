"""The loader is strict: malformed packs raise TaxonomyError with a pointed message."""

from __future__ import annotations

import textwrap

import pytest

from ladex.engine.taxonomy import (
    TaxonomyError,
    aggregate,
    parse_pack,
)

VALID_PACK = textwrap.dedent(
    """
    schema_version: 1
    name: sample
    version: 0.1.0
    rules:
      - id: openai.import
        name: OpenAI import
        component_type: inference_api
        match: { kind: import, module: openai }
    """
)


def test_valid_pack_parses() -> None:
    pack = parse_pack(VALID_PACK, source="sample")
    assert pack.name == "sample"
    assert pack.rules[0].id == "openai.import"


def test_top_level_must_be_mapping() -> None:
    with pytest.raises(TaxonomyError, match="must be a mapping"):
        parse_pack("- just\n- a\n- list\n", source="bad")


def test_invalid_yaml_is_reported() -> None:
    with pytest.raises(TaxonomyError, match="not valid YAML"):
        parse_pack("name: [unterminated\n", source="bad")


def test_unsupported_schema_version_rejected() -> None:
    text = VALID_PACK.replace("schema_version: 1", "schema_version: 99")
    with pytest.raises(TaxonomyError, match="not supported"):
        parse_pack(text, source="bad")


def test_unknown_key_is_rejected() -> None:
    text = textwrap.dedent(
        """
        schema_version: 1
        name: sample
        version: 0.1.0
        rules:
          - id: openai.import
            name: OpenAI import
            component_type: inference_api
            match: { kind: import, module: openai }
            oops: true
        """
    )
    with pytest.raises(TaxonomyError, match="oops"):
        parse_pack(text, source="bad")


def test_unknown_component_type_rejected() -> None:
    text = VALID_PACK.replace("inference_api", "teleporter")
    with pytest.raises(TaxonomyError, match="component_type"):
        parse_pack(text, source="bad")


def test_unknown_match_kind_rejected() -> None:
    text = VALID_PACK.replace("kind: import, module: openai", "kind: telepathy, module: openai")
    with pytest.raises(TaxonomyError):
        parse_pack(text, source="bad")


def test_call_match_arg_is_optional_and_validated() -> None:
    ok = textwrap.dedent(
        """
        schema_version: 1
        name: sample
        version: 0.1.0
        rules:
          - id: bedrock.client
            name: Bedrock
            component_type: inference_api
            match: { kind: call, target: boto3.client, arg: "^bedrock" }
        """
    )
    pack = parse_pack(ok, source="ok")
    assert pack.rules[0].match.arg == "^bedrock"  # type: ignore[union-attr]

    bad = ok.replace('arg: "^bedrock"', 'arg: "[unclosed"')
    with pytest.raises(TaxonomyError, match="invalid arg regex"):
        parse_pack(bad, source="bad")


def test_bad_regex_in_string_match_rejected() -> None:
    text = textwrap.dedent(
        """
        schema_version: 1
        name: sample
        version: 0.1.0
        rules:
          - id: bad.regex
            name: Bad regex
            component_type: model
            match: { kind: string, pattern: "[unclosed" }
        """
    )
    with pytest.raises(TaxonomyError, match="invalid regex"):
        parse_pack(text, source="bad")


def test_malformed_id_rejected() -> None:
    text = VALID_PACK.replace("openai.import", "Openai Import")
    with pytest.raises(TaxonomyError, match="must be lowercase"):
        parse_pack(text, source="bad")


def test_duplicate_id_within_pack_rejected() -> None:
    text = textwrap.dedent(
        """
        schema_version: 1
        name: sample
        version: 0.1.0
        rules:
          - id: dup.rule
            name: One
            component_type: model
            match: { kind: import, module: a }
          - id: dup.rule
            name: Two
            component_type: model
            match: { kind: import, module: b }
        """
    )
    with pytest.raises(TaxonomyError, match="duplicate rule id"):
        parse_pack(text, source="bad")


def test_duplicate_id_across_packs_rejected() -> None:
    pack_a = parse_pack(VALID_PACK, source="a")
    pack_b = parse_pack(VALID_PACK, source="b")
    with pytest.raises(TaxonomyError, match="duplicate rule id"):
        aggregate([pack_a, pack_b])


def test_empty_pack_rejected() -> None:
    text = "schema_version: 1\nname: empty\nversion: 0.1.0\nrules: []\n"
    with pytest.raises(TaxonomyError):
        parse_pack(text, source="bad")
