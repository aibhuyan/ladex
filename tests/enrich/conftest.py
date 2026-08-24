"""Shared test doubles for enrichment: a scripted Fetcher that never touches the network."""

from __future__ import annotations

from typing import Any

import pytest

from ladex.engine.enrich.http import FetchResult


class FakeFetcher:
    """A Fetcher that replays scripted responses and records the URLs it was asked for."""

    def __init__(self, responses: dict[str, FetchResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[str] = []

    def fetch_json(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> FetchResult:
        self.calls.append(url)
        if url in self.responses:
            return self.responses[url]
        return FetchResult(ok=False, status=404, error="http 404")


def ok(data: Any) -> FetchResult:
    return FetchResult(ok=True, status=200, data=data)


def http_error(status: int = 500) -> FetchResult:
    return FetchResult(ok=False, status=status, error=f"http {status}")


@pytest.fixture
def fake_fetcher() -> FakeFetcher:
    return FakeFetcher()
