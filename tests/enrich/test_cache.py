"""The TTL cache and the cache-first / stale-fallback / offline fetch policy."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from ladex.engine.enrich.cache import Cache, cached_json
from ladex.engine.enrich.models import EnrichStatus

from .conftest import http_error, ok


def _cache(tmp_path: Path, ttl: timedelta = timedelta(days=7)) -> Cache:
    return Cache(root=tmp_path, ttl=ttl)


def test_live_then_cache(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    calls = {"n": 0}

    def fetch() -> object:
        calls["n"] += 1
        return ok({"v": 1})

    data, status = cached_json(cache, "ns", "k", offline=False, fetch=fetch)  # type: ignore[arg-type]
    assert status == EnrichStatus.LIVE
    assert data == {"v": 1}

    # Second call within TTL must be served from cache without fetching again.
    data, status = cached_json(cache, "ns", "k", offline=False, fetch=fetch)  # type: ignore[arg-type]
    assert status == EnrichStatus.CACHE
    assert calls["n"] == 1


def test_expired_entry_refetches(tmp_path: Path) -> None:
    cache = _cache(tmp_path, ttl=timedelta(seconds=-1))  # everything is instantly stale
    cache.set("ns", "k", {"old": True})
    data, status = cached_json(cache, "ns", "k", offline=False, fetch=lambda: ok({"new": True}))
    assert status == EnrichStatus.LIVE
    assert data == {"new": True}


def test_network_failure_falls_back_to_stale(tmp_path: Path) -> None:
    cache = _cache(tmp_path, ttl=timedelta(seconds=-1))
    cache.set("ns", "k", {"cached": True})
    data, status = cached_json(cache, "ns", "k", offline=False, fetch=lambda: http_error(503))
    assert status == EnrichStatus.STALE
    assert data == {"cached": True}


def test_network_failure_without_cache_is_error(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    data, status = cached_json(cache, "ns", "k", offline=False, fetch=lambda: http_error(503))
    assert status == EnrichStatus.ERROR
    assert data is None


def test_404_is_not_found(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    data, status = cached_json(cache, "ns", "k", offline=False, fetch=lambda: http_error(404))
    assert status == EnrichStatus.NOT_FOUND
    assert data is None


def test_offline_uses_cache_only(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    cache.set("ns", "k", {"cached": True})

    def fetch() -> object:
        raise AssertionError("offline must never fetch")

    data, status = cached_json(cache, "ns", "k", offline=True, fetch=fetch)  # type: ignore[arg-type]
    assert status == EnrichStatus.CACHE
    assert data == {"cached": True}


def test_offline_without_cache_is_offline_status(tmp_path: Path) -> None:
    cache = _cache(tmp_path)
    data, status = cached_json(cache, "ns", "missing", offline=True, fetch=lambda: ok({}))
    assert status == EnrichStatus.OFFLINE
    assert data is None
