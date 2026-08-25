"""Detection of the providers/stores added after the dogfood pass (FN gaps it surfaced)."""

from __future__ import annotations

import textwrap

import pytest

from ladex.engine.detect import PythonDetector


@pytest.fixture(scope="module")
def detector() -> PythonDetector:
    return PythonDetector()


def _ids(detector: PythonDetector, code: str) -> set[str]:
    return {d.rule_id for d in detector.detect_source(textwrap.dedent(code))}


def test_google_gemini_both_sdks(detector: PythonDetector) -> None:
    legacy = _ids(detector, "import google.generativeai as genai\ngenai.GenerativeModel('x')")
    assert {"google-gemini.import", "google-gemini.model"} <= legacy
    new = _ids(detector, "from google import genai\ngenai.Client()")
    assert {"google-genai.import", "google-genai.client"} <= new
    assert "google.model-id" in _ids(detector, 'M = "gemini-1.5-pro"')


def test_litellm(detector: PythonDetector) -> None:
    ids = _ids(detector, "import litellm\nlitellm.completion(model='gpt-4o', messages=[])")
    assert {"litellm.import", "litellm.completion"} <= ids


def test_cohere_mistral_ollama(detector: PythonDetector) -> None:
    assert "cohere.client" in _ids(detector, "import cohere\ncohere.Client()")
    assert "mistral.client" in _ids(detector, "from mistralai import Mistral\nMistral()")
    assert "ollama.chat" in _ids(detector, "import ollama\nollama.chat(model='llama3')")


def test_vector_stores_chroma_weaviate_qdrant(detector: PythonDetector) -> None:
    assert "chroma.persistent-client" in _ids(
        detector, "import chromadb\nchromadb.PersistentClient(path='db')"
    )
    assert "weaviate.connect-local" in _ids(
        detector, "import weaviate\nweaviate.connect_to_local()"
    )
    assert "qdrant.client" in _ids(
        detector, "from qdrant_client import QdrantClient\nQdrantClient(url='x')"
    )


def test_sentence_transformers_import_and_call(detector: PythonDetector) -> None:
    ids = _ids(
        detector,
        "from sentence_transformers import SentenceTransformer\nSentenceTransformer('m')",
    )
    assert {"sentence-transformers.import", "sentence-transformers.model"} <= ids


def test_voyageai(detector: PythonDetector) -> None:
    ids = _ids(detector, "import voyageai\nvo = voyageai.Client()\nM = 'voyage-3-large'")
    assert {"voyageai.import", "voyageai.client", "voyageai.model-id"} <= ids


def test_bedrock_arg_aware_match(detector: PythonDetector) -> None:
    # Only a boto3 client for a Bedrock service counts as AI.
    assert "aws-bedrock.client" in _ids(detector, 'import boto3\nboto3.client("bedrock-runtime")')
    assert "aws-bedrock.client" in _ids(detector, 'import boto3\nboto3.client("bedrock")')


def test_bedrock_does_not_fire_on_other_boto3_clients(detector: PythonDetector) -> None:
    # boto3.client("s3") / a non-string arg must NOT be flagged (no false positive).
    assert _ids(detector, 'import boto3\nboto3.client("s3")') == set()
    assert _ids(detector, "import boto3\nsvc = 'bedrock-runtime'\nboto3.client(svc)") == set()


def test_still_silent_on_non_ai(detector: PythonDetector) -> None:
    # Guard against the new rules widening into false positives.
    assert _ids(detector, "import os\nimport cohere_lookalike\nx = 'gemini valley'") == set()
