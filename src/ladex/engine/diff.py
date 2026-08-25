"""Diff the AI components between two scans — "what did this change add or remove?".

The PR-check surface uses this to report a *delta* ("this PR introduces OpenAI and a model
with UNDOCUMENTED provenance") instead of re-listing the whole repo. Detections are collapsed
into stable component identities so the diff is about logical components, not raw line hits.
"""

from __future__ import annotations

from dataclasses import dataclass

from ladex.engine.detect import Detection
from ladex.engine.scan import ScanResult
from ladex.engine.taxonomy.models import ComponentType


@dataclass(frozen=True, slots=True)
class DiffComponent:
    """A logical AI component, identified by a stable key for set diffing."""

    key: str
    kind: str
    label: str

    def sort_key(self) -> tuple[str, str]:
        return (self.kind, self.label)


def _component_for(det: Detection) -> DiffComponent:
    kind = det.component_type.value
    if det.component_type is ComponentType.MODEL:
        return DiffComponent(key=f"model::{det.evidence}", kind=kind, label=det.evidence)
    if det.match_kind == "resource":  # IaC finding
        sev = f" [{det.severity}]" if det.severity else ""
        return DiffComponent(
            key=f"iac::{det.rule_id}::{det.evidence}",
            kind=kind,
            label=f"{det.evidence}{sev}",
        )
    provider = det.provider or det.evidence.split(".", 1)[0]
    return DiffComponent(key=f"{kind}::{provider}", kind=kind, label=f"{provider} ({kind})")


def scan_components(scan: ScanResult) -> dict[str, DiffComponent]:
    """Collapse a scan's detections into distinct logical components, keyed for diffing."""
    out: dict[str, DiffComponent] = {}
    for det in scan.detections:
        comp = _component_for(det)
        out[comp.key] = comp
    return out


@dataclass(frozen=True, slots=True)
class BomDiff:
    """Components added and removed going from a base scan to a head scan."""

    added: tuple[DiffComponent, ...] = ()
    removed: tuple[DiffComponent, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def diff_scans(base: ScanResult, head: ScanResult) -> BomDiff:
    """Compute the component delta from ``base`` to ``head``."""
    b = scan_components(base)
    h = scan_components(head)
    added = sorted((h[k] for k in h.keys() - b.keys()), key=DiffComponent.sort_key)
    removed = sorted((b[k] for k in b.keys() - h.keys()), key=DiffComponent.sort_key)
    return BomDiff(added=tuple(added), removed=tuple(removed))


def render_diff_markdown(diff: BomDiff) -> str:
    """Render a component diff as Markdown (for the PR comment / job summary)."""
    if not diff.changed:
        return "### AI changes\n\nNo AI components added or removed by this change.\n"
    lines = ["### AI changes in this diff", ""]
    for comp in diff.added:
        lines.append(f"- **+ added** {_md(comp.label)} _({comp.kind})_")
    for comp in diff.removed:
        lines.append(f"- **- removed** {_md(comp.label)} _({comp.kind})_")
    lines.append("")
    return "\n".join(lines) + "\n"


def _md(text: str) -> str:
    return text.replace("|", "\\|")
