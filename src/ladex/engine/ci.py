"""CI reporting: turn a scan + policy + attestations into a gate decision for PR checks.

This is the engine behind the GitHub PR-check surface (and `ladex ci`). It reuses the same
detector, policy evaluator, and attestation store as every other surface, then distinguishes
**action-required gaps** (things a human must resolve before merge) from informational
findings, and produces a pass/fail verdict plus a Markdown report a PR comment can render.

Gaps are deliberately low-noise:
- **provenance** — a *loadable* model (a Hugging Face ``org/name`` repo) whose provenance or
  consent basis is UNDOCUMENTED and not covered by a verified attestation. Hosted-API model
  names (``gpt-4o``, ``claude-*``) are not gated — you don't own their weights.
- **obligation** — an EU AI Act obligation that *applies* and requires a human attestation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ladex.engine.attest import OBLIGATION_CLAIM, AttestationStore, verify_attestation
from ladex.engine.diff import BomDiff, diff_scans, render_diff_markdown
from ladex.engine.enrich.hfhub import looks_like_repo_id
from ladex.engine.policy import ProjectContext, check_scan, obligation_fingerprint
from ladex.engine.policy.models import Severity
from ladex.engine.policy.report import PolicyReport
from ladex.engine.scan import ScanResult, scan_path
from ladex.engine.taxonomy.models import ComponentType

_GAP_ORDER = {"prohibited": 0, "provenance": 1, "obligation": 2}

ATTESTABLE_MODEL_CLAIMS = ("provenance", "consent_basis")


class FailOn(StrEnum):
    """How strict the gate is."""

    NONE = "none"  # always pass (report only)
    GAPS = "gaps"  # fail on action-required gaps (default for a check)
    STRICT = "strict"  # also fail when obligations *may* apply (undeclared project facts)


@dataclass(frozen=True, slots=True)
class Gap:
    """One item a human must resolve before the check can pass."""

    kind: str  # "provenance" | "obligation"
    subject: str
    summary: str
    remedy: str
    citation: str | None = None


@dataclass(frozen=True, slots=True)
class CiReport:
    root: Path
    scan: ScanResult
    policy: PolicyReport
    gaps: tuple[Gap, ...] = ()
    warnings: tuple[str, ...] = ()
    fail_on: FailOn = FailOn.GAPS
    #: Component delta vs a base tree, when `ladex ci --base` is used.
    diff: BomDiff | None = None

    @property
    def passed(self) -> bool:
        if self.fail_on is FailOn.NONE:
            return True
        if self.fail_on is FailOn.STRICT:
            return not self.gaps and not self.warnings
        return not self.gaps

    @property
    def provenance_gaps(self) -> tuple[Gap, ...]:
        return tuple(g for g in self.gaps if g.kind == "provenance")

    @property
    def obligation_gaps(self) -> tuple[Gap, ...]:
        return tuple(g for g in self.gaps if g.kind == "obligation")


def build_ci_report(
    root: Path,
    project: ProjectContext | None = None,
    *,
    fail_on: FailOn = FailOn.GAPS,
    scan: ScanResult | None = None,
    base: Path | None = None,
) -> CiReport:
    """Assemble the CI gate report for ``root``.

    When ``base`` (a checkout of the base branch/tree) is given, the report includes the
    component delta ("what this change adds/removes").
    """
    project = project or ProjectContext()
    result = scan if scan is not None else scan_path(root)
    policy = check_scan(result, project)
    diff = diff_scans(scan_path(base), result) if base is not None else None

    attestations = AttestationStore.for_root(root).load()
    verified = {(a.subject, a.claim) for a in attestations if verify_attestation(a)}
    # Verified obligation sign-offs, keyed by rule id (to compare the bound rule hash).
    oblig_att = {
        a.subject: a for a in attestations if a.claim == OBLIGATION_CLAIM and verify_attestation(a)
    }

    gaps: list[Gap] = []

    # Provenance gaps: loadable models whose UNDOCUMENTED fields aren't attested.
    seen: set[tuple[str, str]] = set()
    for det in result.detections:
        if det.component_type is not ComponentType.MODEL:
            continue
        if not looks_like_repo_id(det.evidence):
            continue  # hosted-API model name, not weights we own
        for claim in ATTESTABLE_MODEL_CLAIMS:
            key = (det.evidence, claim)
            if key in seen or key in verified:
                continue
            seen.add(key)
            gaps.append(
                Gap(
                    kind="provenance",
                    subject=det.evidence,
                    summary=f"{claim.replace('_', ' ')} is UNDOCUMENTED for {det.evidence}",
                    remedy=(
                        f'ladex attest "{det.evidence}" --claim {claim} '
                        f'--value "..." --attester you@org'
                    ),
                )
            )

    # Obligation gaps. Prohibited practices (Art. 5) are a hard stop — they can NEVER be
    # attested away. Other applicable requires-attestation obligations close on a verified
    # "satisfied" attestation for the rule.
    for ob in policy.applies:
        if not ob.is_gap:
            continue
        if ob.severity is Severity.PROHIBITED:
            gaps.append(
                Gap(
                    kind="prohibited",
                    subject=ob.rule_id,
                    summary=f"{ob.citation}: {ob.title}",
                    remedy="Remove it - Art. 5 prohibits this; it cannot be attested away.",
                    citation=ob.citation,
                )
            )
        else:
            current = obligation_fingerprint(
                citation=ob.citation,
                title=ob.title,
                obligation=ob.obligation,
                verification=ob.verification.value,
            )
            att = oblig_att.get(ob.rule_id)
            if att is not None and att.bindings.get("rule_hash") == current:
                continue  # signed off against the current rule text — closed
            stale = att is not None  # attested, but the rule text has since changed
            note = " (prior sign-off is stale - the rule changed; re-attest)" if stale else ""
            gaps.append(
                Gap(
                    kind="obligation",
                    subject=ob.rule_id,
                    summary=f"{ob.citation}: {ob.title}{note}",
                    remedy=(
                        f"ladex attest {ob.rule_id} --claim {OBLIGATION_CLAIM} "
                        f'--value "how it is satisfied" --attester you@org'
                    ),
                    citation=ob.citation,
                )
            )

    gaps.sort(key=lambda g: (_GAP_ORDER.get(g.kind, 9), g.subject))

    warnings = tuple(
        f"{ob.citation}: {ob.title} may apply - declare {', '.join(ob.unresolved)}"
        for ob in policy.potential
    )

    return CiReport(
        root=root,
        scan=result,
        policy=policy,
        gaps=tuple(gaps),
        warnings=warnings,
        fail_on=fail_on,
        diff=diff,
    )


def render_markdown(report: CiReport) -> str:
    """Render the CI report as Markdown for a PR comment / job summary."""
    lines: list[str] = ["## Ladex - AI bill of lading", ""]
    verdict = "PASS" if report.passed else "ACTION REQUIRED"
    n = len(report.scan.detections)
    files = report.scan.files_with_findings
    lines.append(f"**{verdict}** - {n} AI detection(s) across {files} file(s).")
    lines.append("")

    by_type = report.scan.counts_by_component_type()
    if by_type:
        summary = ", ".join(f"{k}: {v}" for k, v in by_type.items())
        lines.append(f"_Components:_ {summary}")
        lines.append("")

    if report.gaps:
        lines.append("### Action required")
        lines.append("")
        lines.append("| Type | Item | How to resolve |")
        lines.append("| --- | --- | --- |")
        for g in report.gaps:
            lines.append(f"| {g.kind} | {_md(g.summary)} | `{_md(g.remedy)}` |")
        lines.append("")

    if report.warnings:
        lines.append("### May apply (declare project facts)")
        lines.append("")
        for w in report.warnings:
            lines.append(f"- {_md(w)}")
        lines.append("")

    if not report.gaps and not report.warnings:
        lines.append("No open obligations or documentation gaps. ")
        lines.append("")

    if report.diff is not None:
        lines.append(render_diff_markdown(report.diff))

    lines.append("<sub>Generated by Ladex. Provenance and consent basis can't be derived by ")
    lines.append("any scanner - they require a signed human attestation.</sub>")
    return "\n".join(lines) + "\n"


def _md(text: str) -> str:
    """Escape the Markdown table cell separator."""
    return text.replace("|", "\\|")
