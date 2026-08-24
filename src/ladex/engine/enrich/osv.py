"""OSV enrichment: known vulnerabilities for a PyPI package at a given version.

Wraps the OSV.dev query API. We never build our own CVE matcher — OSV is the free,
authoritative source ("wrap, don't rebuild").

Version caveat: from source alone Ladex does not know the *pinned* version in the target
environment, so callers pass the resolved PyPI latest version. A future syft integration
will supply the exact installed version; until then, results describe the latest release.
"""

from __future__ import annotations

from typing import Any

from ladex.engine.enrich.cache import Cache, cached_json
from ladex.engine.enrich.http import Fetcher
from ladex.engine.enrich.models import EnrichStatus, Vuln

_OSV_QUERY = "https://api.osv.dev/v1/query"


def fetch_vulns(
    name: str, version: str, fetcher: Fetcher, cache: Cache, *, offline: bool
) -> tuple[tuple[Vuln, ...], EnrichStatus]:
    body = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
    data, status = cached_json(
        cache,
        "osv",
        f"{name}@{version}",
        offline=offline,
        fetch=lambda: fetcher.fetch_json(_OSV_QUERY, method="POST", json_body=body),
    )
    if not isinstance(data, dict):
        return (), status
    vulns = tuple(_parse_vuln(v) for v in data.get("vulns", []) or [])
    return vulns, status


def _parse_vuln(raw: dict[str, Any]) -> Vuln:
    return Vuln(
        id=raw.get("id", "UNKNOWN"),
        aliases=tuple(raw.get("aliases", []) or []),
        summary=raw.get("summary"),
        severity=_severity(raw),
    )


def _severity(raw: dict[str, Any]) -> str | None:
    for entry in raw.get("severity", []) or []:
        score = entry.get("score")
        if score:
            return str(score)
    return None
