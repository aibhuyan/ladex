"""A tiny TTL disk cache and the fetch policy that makes enrichment offline-capable.

``cached_json`` centralizes the offline / stale / rate-limit behaviour so every provider
gets it for free:

- **offline** → use the cache (fresh or stale) and never touch the network;
- **fresh cache** → serve it without a request (this is the rate-limit protection);
- **network ok** → store and serve the fresh payload;
- **network fails but a stale entry exists** → serve stale rather than nothing;
- **nothing anywhere** → an honest ERROR/OFFLINE/NOT_FOUND status, never a fabricated value.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import platformdirs

from ladex.engine.enrich.http import FetchResult
from ladex.engine.enrich.models import EnrichStatus

DEFAULT_TTL = timedelta(days=7)


def default_cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir("ladex")) / "enrich"


@dataclass(frozen=True, slots=True)
class CacheEntry:
    data: Any
    fetched_at: datetime
    is_fresh: bool


class Cache:
    """Namespaced JSON file cache under a root directory."""

    def __init__(self, root: Path | None = None, ttl: timedelta = DEFAULT_TTL) -> None:
        self._root = root if root is not None else default_cache_dir()
        self._ttl = ttl

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()  # noqa: S324 - cache key, not security
        return self._root / namespace / f"{digest}.json"

    def get(self, namespace: str, key: str) -> CacheEntry | None:
        path = self._path(namespace, key)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = datetime.fromisoformat(raw["fetched_at"])
            data = raw["data"]
        except (OSError, ValueError, KeyError):
            return None
        is_fresh = datetime.now(UTC) - fetched_at < self._ttl
        return CacheEntry(data=data, fetched_at=fetched_at, is_fresh=is_fresh)

    def set(self, namespace: str, key: str, data: Any) -> None:
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"key": key, "fetched_at": datetime.now(UTC).isoformat(), "data": data}
        path.write_text(json.dumps(payload), encoding="utf-8")


def cached_json(
    cache: Cache,
    namespace: str,
    key: str,
    *,
    offline: bool,
    fetch: Callable[[], FetchResult],
) -> tuple[Any | None, EnrichStatus]:
    """Apply the cache-first / stale-fallback / offline policy to one lookup."""
    entry = cache.get(namespace, key)

    if offline:
        if entry is None:
            return None, EnrichStatus.OFFLINE
        return entry.data, (EnrichStatus.CACHE if entry.is_fresh else EnrichStatus.STALE)

    if entry is not None and entry.is_fresh:
        return entry.data, EnrichStatus.CACHE

    result = fetch()
    if result.ok:
        cache.set(namespace, key, result.data)
        return result.data, EnrichStatus.LIVE
    if result.status == 404:
        return None, EnrichStatus.NOT_FOUND
    if entry is not None:  # network failed — fall back to whatever we have
        return entry.data, EnrichStatus.STALE
    return None, EnrichStatus.ERROR
