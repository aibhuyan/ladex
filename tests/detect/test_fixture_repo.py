"""Integration: run detection over the fixture repo of known AI code."""

from __future__ import annotations

from pathlib import Path

import pytest

from ladex.engine.detect import Detection, PythonDetector

REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


@pytest.fixture(scope="module")
def detector() -> PythonDetector:
    return PythonDetector()


def _detect(detector: PythonDetector, name: str) -> list[Detection]:
    return detector.detect_file(REPO / name)


def test_agents_file(detector: PythonDetector) -> None:
    ids = {d.rule_id for d in _detect(detector, "agents.py")}
    assert {
        "openai.import",
        "anthropic.import",
        "langchain.import",
        "openai.client",
        "anthropic.client",
        "openai.model-id",
        "anthropic.model-id",
    } <= ids


def test_models_file(detector: PythonDetector) -> None:
    ids = {d.rule_id for d in _detect(detector, "models.py")}
    assert {
        "transformers.import",
        "huggingface-hub.import",
        "transformers.pipeline",
        "huggingface-hub.hf-hub-download",
        "huggingface.sentence-transformers-id",
    } <= ids


def test_store_file(detector: PythonDetector) -> None:
    ids = {d.rule_id for d in _detect(detector, "store.py")}
    assert "pinecone.import" in ids
    assert "pinecone.client" in ids
    assert "pinecone.index" not in ids  # instance method, correctly not matched


def test_noise_file_is_completely_silent(detector: PythonDetector) -> None:
    assert _detect(detector, "noise.py") == []


def test_broken_file_recovers(detector: PythonDetector) -> None:
    ids = {d.rule_id for d in _detect(detector, "broken.py")}
    assert "openai.import" in ids  # tree-sitter recovered the valid import


def test_detections_carry_provider_and_location(detector: PythonDetector) -> None:
    det = next(d for d in _detect(detector, "agents.py") if d.rule_id == "openai.client")
    assert det.provider == "OpenAI"
    assert det.location().startswith(str(REPO))
    assert det.span.start_line > 0
