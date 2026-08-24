"""Build a deterministic CycloneDX ML-BOM from a scan (+ optional enrichment / policy).

The output artifact is the entire product differentiation, so two properties are
non-negotiable:

- **Spec-compliant** — we build it with ``cyclonedx-python-lib`` rather than hand-rolling
  JSON, so it validates against the CycloneDX schema.
- **Deterministic** — the same inputs must produce byte-identical output, or the BOM can't
  be committed and diffed in PRs. The library defaults to a random ``serialNumber``, a
  ``metadata.timestamp`` of *now*, and random per-component ``bom-ref``s; we neutralise all
  three (a serial derived from the project name, no timestamp, explicit stable bom-refs) and
  rely on the library's sorted component set for stable ordering.

Honest gaps are carried into the artifact: every model records ``ladex:provenance`` and
``ladex:consent_basis`` as ``UNDOCUMENTED`` properties — the fields a human attestation
(Step 7) will later fill in, never a fabricated value.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field

from cyclonedx.contrib.license.factories import LicenseFactory
from cyclonedx.model import ExternalReference, ExternalReferenceType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from ladex import __version__
from ladex.engine.attest.service import verify_attestation
from ladex.engine.attest.store import Attestation
from ladex.engine.enrich.models import EnrichedModel, EnrichedPackage, EnrichmentReport
from ladex.engine.enrich.pypi import module_to_distribution
from ladex.engine.policy.report import PolicyReport
from ladex.engine.scan import ScanResult
from ladex.engine.taxonomy.models import ComponentType as LadexType

# A stable namespace so a project's serialNumber is derived, not random.
_LADEX_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
_PROP = "ladex:"

_license_factory = LicenseFactory()


@dataclass
class _PackageEntry:
    """Aggregated detection facts for one PyPI distribution."""

    component_types: set[str] = field(default_factory=set)
    providers: set[str] = field(default_factory=set)


def build_bom(
    result: ScanResult,
    *,
    enrichment: EnrichmentReport | None = None,
    policy: PolicyReport | None = None,
    attestations: Sequence[Attestation] | None = None,
    project_name: str | None = None,
) -> Bom:
    """Assemble a deterministic CycloneDX BOM describing the AI cargo in a scan."""
    name = project_name or _infer_name(result)
    bom = Bom()
    _strip_nondeterminism(bom, name)
    bom.metadata.tools.components.add(
        Component(name="ladex", version=__version__, type=ComponentType.APPLICATION)
    )
    root = Component(name=name, type=ComponentType.APPLICATION, bom_ref="root")
    bom.metadata.component = root

    pkg_enrich = enrichment.packages if enrichment else {}
    model_enrich = enrichment.models if enrichment else {}
    # Only signatures that actually verify may fill a gap — honest gaps to the last step.
    attested = {(a.subject, a.claim): a for a in (attestations or ()) if verify_attestation(a)}

    for dist, entry in sorted(_package_index(result).items()):
        _add_package_component(bom, dist, entry, pkg_enrich.get(dist))

    for model_id in _model_ids(result):
        _add_model_component(bom, model_id, model_enrich.get(model_id), attested)

    # Root depends on every detected component, completing the dependency graph.
    bom.register_dependency(root, list(bom.components))

    if policy is not None:
        _attach_policy(bom, policy)

    return bom


def render_json(bom: Bom) -> str:
    """Serialize a BOM to deterministic pretty JSON (CycloneDX 1.6)."""
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return outputter.output_as_string(indent=2) + "\n"


# -- derivation -------------------------------------------------------------


def _package_index(result: ScanResult) -> dict[str, _PackageEntry]:
    """Map each detected PyPI distribution to its aggregated component facts."""
    index: dict[str, _PackageEntry] = {}
    for det in result.detections:
        if det.match_kind == "string":
            continue  # string detections are models, handled separately
        top = det.evidence.split(".", 1)[0]
        if not top:
            continue
        dist = module_to_distribution(top)
        entry = index.setdefault(dist, _PackageEntry())
        entry.component_types.add(det.component_type.value)
        if det.provider:
            entry.providers.add(det.provider)
    return index


def _model_ids(result: ScanResult) -> list[str]:
    return sorted(
        {det.evidence for det in result.detections if det.component_type is LadexType.MODEL}
    )


# -- component builders -----------------------------------------------------


def _add_package_component(
    bom: Bom, dist: str, entry: _PackageEntry, enriched: EnrichedPackage | None
) -> None:
    version = enriched.pypi.version if enriched else None
    bom_ref = f"pkg:pypi/{dist}" + (f"@{version}" if version else "")
    comp = Component(
        name=dist,
        version=version,
        type=ComponentType.LIBRARY,
        bom_ref=bom_ref,
        purl=PackageURL("pypi", name=dist, version=version),
    )
    comp.properties.add(
        Property(name=f"{_PROP}component_type", value=",".join(sorted(entry.component_types)))
    )
    for provider in sorted(entry.providers):
        comp.properties.add(Property(name=f"{_PROP}provider", value=provider))
    if enriched and enriched.pypi.license:
        comp.licenses.add(_license_factory.make_from_string(enriched.pypi.license))
    for vuln in enriched.vulns if enriched else ():
        comp.properties.add(Property(name=f"{_PROP}cve", value=vuln.id))
    bom.components.add(comp)


def _add_model_component(
    bom: Bom,
    model_id: str,
    enriched: EnrichedModel | None,
    attested: dict[tuple[str, str], Attestation],
) -> None:
    comp = Component(
        name=model_id,
        type=ComponentType.MACHINE_LEARNING_MODEL,
        bom_ref=f"model:{model_id}",
    )
    if enriched and enriched.hf.license:
        comp.licenses.add(_license_factory.make_from_string(enriched.hf.license))
    if enriched and enriched.hf.base_model:
        comp.properties.add(Property(name=f"{_PROP}base_model", value=enriched.hf.base_model))
    if "/" in model_id:
        comp.external_references.add(
            ExternalReference(
                type=ExternalReferenceType.WEBSITE,
                url=XsUri(f"https://huggingface.co/{model_id}"),
            )
        )
    # A verified attestation fills the gap; otherwise it stays UNDOCUMENTED. Never a fake value.
    for claim in ("provenance", "consent_basis"):
        att = attested.get((model_id, claim))
        if att is not None:
            comp.properties.add(Property(name=f"{_PROP}{claim}", value=att.value))
            comp.properties.add(Property(name=f"{_PROP}{claim}.attester", value=att.attester))
            comp.properties.add(
                Property(name=f"{_PROP}{claim}.attestation", value=json.dumps(att.envelope))
            )
        else:
            comp.properties.add(Property(name=f"{_PROP}{claim}", value="UNDOCUMENTED"))
    bom.components.add(comp)


def _attach_policy(bom: Bom, policy: PolicyReport) -> None:
    for ob in policy.obligations:
        bom.metadata.properties.add(
            Property(
                name=f"{_PROP}obligation:{ob.rule_id}",
                value=f"{ob.status.value}|{ob.verification.value}|{ob.citation}",
            )
        )


# -- determinism & helpers --------------------------------------------------


def _strip_nondeterminism(bom: Bom, seed: str) -> None:
    # A serialNumber derived from the project name is stable run-to-run; the timestamp is
    # dropped entirely so an unchanged project yields an unchanged BOM. (The library types
    # timestamp as non-optional, but None is valid and simply omits it from output.)
    bom.serial_number = uuid.uuid5(_LADEX_NS, seed)
    bom.metadata.timestamp = None  # type: ignore[assignment]


def _infer_name(result: ScanResult) -> str:
    return result.root.name or "project"
