"""A thin, injectable HTTP-JSON fetcher.

Providers depend on the :class:`Fetcher` protocol, never on httpx directly, so tests can
substitute a fake that returns canned payloads — no network access in CI. The real
implementation, :class:`HttpFetcher`, wraps httpx with a timeout, a descriptive User-Agent,
and transport-level retries (basic rate-limit resilience).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ladex import __version__

_USER_AGENT = f"ladex/{__version__} (+https://ladex.dev)"


@dataclass(frozen=True, slots=True)
class FetchResult:
    """The outcome of one JSON fetch. ``ok`` implies ``data`` is populated."""

    ok: bool
    status: int
    data: Any | None = None
    error: str | None = None


class Fetcher(Protocol):
    """Anything that can fetch JSON. Implemented by httpx in prod, a fake in tests."""

    def fetch_json(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResult: ...


class HttpFetcher:
    """The production :class:`Fetcher`, backed by a lazily-created httpx client."""

    def __init__(self, timeout: float = 10.0, retries: int = 2) -> None:
        self._timeout = timeout
        self._retries = retries
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self._timeout,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
                transport=httpx.HTTPTransport(retries=self._retries),
                follow_redirects=True,
            )
        return self._client

    def fetch_json(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResult:
        try:
            resp = self._get_client().request(method, url, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            return FetchResult(ok=False, status=0, error=str(exc))
        if resp.status_code == 200:
            try:
                return FetchResult(ok=True, status=200, data=resp.json())
            except ValueError as exc:
                return FetchResult(ok=False, status=200, error=f"invalid JSON: {exc}")
        return FetchResult(ok=False, status=resp.status_code, error=f"http {resp.status_code}")

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
