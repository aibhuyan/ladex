"""Data shapes for enrichment results.

The recurring theme is **honest gaps**: enrichment resolves what a scanner *can* resolve
(a package's license, its known CVEs, a model's declared license) and explicitly refuses to
invent what it cannot. Training-data provenance and consent basis are never derivable from
metadata, so they are carried as the literal string ``UNDOCUMENTED`` — a valuable output
that a human later turns into a signed attestation (Step 7), never a fake green check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

#: The sentinel for a fact no tool can verify; only a human attestation can resolve it.
UNDOCUMENTED = "UNDOCUMENTED"


class EnrichStatus(StrEnum):
    """Where an enrichment fact came from — provenance of the metadata itself."""

    LIVE = "live"  # fetched fresh from the network this run
    CACHE = "cache"  # served from a fresh on-disk cache entry
    STALE = "stale"  # network failed; served an expired cache entry as a fallback
    OFFLINE = "offline"  # offline mode and nothing cached
    NOT_FOUND = "not_found"  # the upstream has no record (e.g. HTTP 404)
    ERROR = "error"  # the lookup failed and there was no cache to fall back on


@dataclass(frozen=True, slots=True)
class PyPIInfo:
    """License and release metadata for a PyPI distribution (auto-verifiable)."""

    name: str
    status: EnrichStatus
    version: str | None = None
    license: str | None = None
    summary: str | None = None
    home_page: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Vuln:
    """One known vulnerability, as reported by OSV (auto-verifiable)."""

    id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class ModelInfo:
    """Declared metadata for a Hugging Face model repo.

    ``license`` and the declared ``datasets`` are auto-verifiable *as declarations* — but a
    declared dataset list is NOT proof of lawful training-data provenance, which is why the
    enclosing :class:`EnrichedModel` still carries ``UNDOCUMENTED`` provenance.
    """

    repo_id: str
    status: EnrichStatus
    license: str | None = None
    base_model: str | None = None
    datasets: tuple[str, ...] = ()
    downloads: int | None = None
    gated: bool | None = None
    tags: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class EnrichedPackage:
    """A referenced package with its version, license, and CVEs resolved.

    ``resolved_version`` is the version actually pinned in the project's lockfile (what ships);
    CVEs are queried against it. When no lockfile pins it, we fall back to PyPI's latest and
    say so via ``version_source`` — an honest "we couldn't pin this" rather than a wrong claim.
    """

    name: str
    pypi: PyPIInfo
    vulns: tuple[Vuln, ...] = ()
    vulns_status: EnrichStatus = EnrichStatus.OFFLINE
    resolved_version: str | None = None
    version_source: str | None = None  # e.g. "uv.lock", "pypi-latest"

    @property
    def effective_version(self) -> str | None:
        """The version CVEs/license describe — the pinned one if known, else PyPI latest."""
        return self.resolved_version or self.pypi.version


@dataclass(frozen=True, slots=True)
class EnrichedModel:
    """A referenced model with declared metadata and explicit provenance gaps."""

    repo_id: str
    hf: ModelInfo
    #: No scanner can derive these — they require a human attestation (Step 7).
    provenance: str = UNDOCUMENTED
    consent_basis: str = UNDOCUMENTED


@dataclass(frozen=True, slots=True)
class EnrichmentReport:
    """Enrichment for a whole scan, keyed by package name / model repo id."""

    offline: bool
    packages: dict[str, EnrichedPackage] = field(default_factory=dict)
    models: dict[str, EnrichedModel] = field(default_factory=dict)

    @property
    def total_vulns(self) -> int:
        return sum(len(p.vulns) for p in self.packages.values())
