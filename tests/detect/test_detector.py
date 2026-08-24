"""Detection behaviour: import resolution, the four match kinds, and graceful recovery."""

from __future__ import annotations

import textwrap

import pytest

from ladex.engine.detect import PythonDetector


@pytest.fixture(scope="module")
def detector() -> PythonDetector:
    return PythonDetector()


def _ids(detector: PythonDetector, code: str) -> set[str]:
    return {d.rule_id for d in detector.detect_source(textwrap.dedent(code))}


# -- imports ---------------------------------------------------------------


def test_plain_import(detector: PythonDetector) -> None:
    assert "openai.import" in _ids(detector, "import openai")


def test_from_import_matches_module_rule(detector: PythonDetector) -> None:
    assert "anthropic.import" in _ids(detector, "from anthropic import Anthropic")


def test_submodule_import_matches_parent(detector: PythonDetector) -> None:
    # `from langchain.agents import x` should still match the `langchain` module rule.
    assert "langchain.import" in _ids(detector, "from langchain.agents import initialize_agent")


def test_similar_but_distinct_package_does_not_match(detector: PythonDetector) -> None:
    # langchain_openai must not be mistaken for the `langchain` rule (underscore != dot).
    ids = _ids(detector, "import langchain_openai")
    assert "langchain.import" not in ids
    assert "langchain.openai-integration" in ids


# -- call resolution through imports ---------------------------------------


def test_call_on_module(detector: PythonDetector) -> None:
    assert "openai.client" in _ids(detector, "import openai\nopenai.OpenAI()")


def test_call_via_from_import(detector: PythonDetector) -> None:
    assert "openai.client" in _ids(detector, "from openai import OpenAI\nOpenAI()")


def test_call_via_aliased_module(detector: PythonDetector) -> None:
    assert "openai.client" in _ids(detector, "import openai as o\no.OpenAI()")


def test_call_via_aliased_symbol(detector: PythonDetector) -> None:
    assert "openai.client" in _ids(detector, "from openai import OpenAI as C\nC()")


def test_nested_classmethod_call(detector: PythonDetector) -> None:
    code = "import transformers\ntransformers.AutoModel.from_pretrained('x')"
    assert "transformers.automodel-from-pretrained" in _ids(detector, code)


def test_unresolved_call_stays_silent(detector: PythonDetector) -> None:
    # No import binding for `OpenAI` -> ruthless silence, no false positive.
    assert _ids(detector, "OpenAI()") == set()


def test_instance_method_is_not_module_attribute(detector: PythonDetector) -> None:
    # `pc.Index(...)` where pc is a local var must not resolve to pinecone.Index.
    code = "from pinecone import Pinecone\npc = Pinecone()\npc.Index('demo')"
    ids = _ids(detector, code)
    assert "pinecone.client" in ids
    assert "pinecone.index" not in ids


# -- string matches --------------------------------------------------------


def test_model_id_string(detector: PythonDetector) -> None:
    assert "openai.model-id" in _ids(detector, 'MODEL = "gpt-4o"')


def test_unrelated_string_is_silent(detector: PythonDetector) -> None:
    assert _ids(detector, 'name = "gpt-like-but-not-a-model"') == set()


# -- positions & determinism ----------------------------------------------


def test_positions_are_one_based_lines(detector: PythonDetector) -> None:
    dets = detector.detect_source("\n\nimport openai")
    imp = next(d for d in dets if d.rule_id == "openai.import")
    assert imp.span.start_line == 3


def test_output_is_sorted_and_stable(detector: PythonDetector) -> None:
    code = "import openai\nimport transformers\nopenai.OpenAI()"
    first = detector.detect_source(code)
    second = detector.detect_source(code)
    assert first == second
    keys = [d.sort_key() for d in first]
    assert keys == sorted(keys)


# -- error tolerance -------------------------------------------------------


def test_invalid_syntax_does_not_raise_and_still_detects(detector: PythonDetector) -> None:
    code = "import openai\ndef broken(:\n    x = openai.OpenAI("
    ids = {d.rule_id for d in detector.detect_source(code)}
    assert "openai.import" in ids
