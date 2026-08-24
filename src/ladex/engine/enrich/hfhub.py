"""Hugging Face Hub enrichment: declared license, base model, datasets for a model repo.

Wraps the public Hub API (``https://huggingface.co/api/models/<repo_id>``). An optional
token (env ``HF_TOKEN`` or ``--hf-token``) is sent only as an ``Authorization`` header to
this host and is never logged or cached in the request. Crucially, whatever a model card
*declares* is not proof of lawful provenance — the caller keeps provenance UNDOCUMENTED.
"""

from __future__ import annotations

from typing import Any

from ladex.engine.enrich.cache import Cache, cached_json
from ladex.engine.enrich.http import Fetcher
from ladex.engine.enrich.models import ModelInfo

_HF_MODEL = "https://huggingface.co/api/models/{repo_id}"


def looks_like_repo_id(evidence: str) -> bool:
    """A Hub repo id is ``org/name`` — a single slash, no spaces."""
    return evidence.count("/") == 1 and " " not in evidence


def fetch_model(
    repo_id: str,
    fetcher: Fetcher,
    cache: Cache,
    *,
    offline: bool,
    token: str | None = None,
) -> ModelInfo:
    headers = {"Authorization": f"Bearer {token}"} if token else None
    data, status = cached_json(
        cache,
        "hfhub",
        repo_id,
        offline=offline,
        fetch=lambda: fetcher.fetch_json(_HF_MODEL.format(repo_id=repo_id), headers=headers),
    )
    if not isinstance(data, dict):
        return ModelInfo(repo_id=repo_id, status=status)
    card = data.get("cardData") or {}
    tags = tuple(data.get("tags", []) or [])
    return ModelInfo(
        repo_id=repo_id,
        status=status,
        license=card.get("license") or _license_from_tags(tags),
        base_model=_first(card.get("base_model")),
        datasets=tuple(_as_list(card.get("datasets"))),
        downloads=data.get("downloads"),
        gated=data.get("gated"),
        tags=tags,
    )


def _license_from_tags(tags: tuple[str, ...]) -> str | None:
    for tag in tags:
        if tag.startswith("license:"):
            return tag.split(":", 1)[1]
    return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _first(value: Any) -> str | None:
    items = _as_list(value)
    return items[0] if items else None
