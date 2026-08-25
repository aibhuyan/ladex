"""The built-in taxonomy packs shipped with Ladex load, validate, and are well-formed."""

from __future__ import annotations

import re

from ladex.engine.taxonomy import (
    ComponentType,
    StringMatch,
    load_builtin_taxonomy,
)

MIN_RULES = 20


def test_builtin_taxonomy_loads() -> None:
    taxonomy = load_builtin_taxonomy()
    assert len(taxonomy) >= MIN_RULES
    assert len(taxonomy.packs) >= 4


def test_rule_ids_are_globally_unique() -> None:
    taxonomy = load_builtin_taxonomy()
    ids = [rule.id for rule in taxonomy.rules]
    assert len(ids) == len(set(ids))


def test_every_component_type_is_a_known_enum() -> None:
    taxonomy = load_builtin_taxonomy()
    for rule in taxonomy.rules:
        assert isinstance(rule.component_type, ComponentType)


def test_string_patterns_all_compile() -> None:
    taxonomy = load_builtin_taxonomy()
    for rule in taxonomy.rules:
        if isinstance(rule.match, StringMatch):
            re.compile(rule.match.pattern)  # would have raised at load time already


def test_expected_headline_rules_are_present() -> None:
    taxonomy = load_builtin_taxonomy()
    for rule_id in (
        "openai.import",
        "openai.client",
        "anthropic.client",
        "langchain.import",
        "langgraph.import",
        "transformers.pipeline",
        "huggingface-hub.hf-hub-download",
        "pinecone.client",
    ):
        assert taxonomy.by_id(rule_id) is not None, f"missing rule {rule_id!r}"


def test_all_target_providers_are_covered() -> None:
    taxonomy = load_builtin_taxonomy()
    providers = {r.provider for r in taxonomy.rules}
    assert {
        "OpenAI",
        "Anthropic",
        "LangChain",
        "Hugging Face",
        "Pinecone",
        # added after the dogfood pass against a real repo
        "Google",
        "Cohere",
        "Mistral",
        "LiteLLM",
        "Ollama",
        "Chroma",
        "Weaviate",
        "Qdrant",
    } <= providers


def test_openai_model_id_pattern_matches_and_rejects() -> None:
    taxonomy = load_builtin_taxonomy()
    rule = taxonomy.by_id("openai.model-id")
    assert rule is not None
    assert isinstance(rule.match, StringMatch)
    pat = re.compile(rule.match.pattern)
    assert pat.match("gpt-4o")
    assert pat.match("gpt-4")
    assert pat.match("o1-preview")
    # Ruthless silence: it must NOT fire on unrelated strings.
    assert not pat.match("logo-4-you")
    assert not pat.match("report")
