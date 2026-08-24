"""Human- and machine-readable rendering of a :class:`ScanResult` for the CLI surface."""

from __future__ import annotations

import os
from typing import Any

from rich.console import Console
from rich.markup import escape

from ladex.engine.detect import Detection
from ladex.engine.enrich import EnrichmentReport
from ladex.engine.enrich.models import EnrichedModel, EnrichedPackage
from ladex.engine.policy import Obligation, PolicyReport
from ladex.engine.policy.report import ObligationStatus
from ladex.engine.scan import ScanResult

_TYPE_STYLE: dict[str, str] = {
    "inference_api": "cyan",
    "model": "magenta",
    "model_loader": "magenta",
    "agent_framework": "yellow",
    "vector_store": "green",
    "dataset": "blue",
    "embeddings": "blue",
}

_EVIDENCE_MAX = 48

# Project-context fact -> the CLI flags that declare it (yes / no).
_PROJECT_FLAGS: dict[str, tuple[str, str]] = {
    "user_facing": ("--user-facing", "--not-user-facing"),
    "generates_synthetic_content": ("--synthetic-content", "--no-synthetic-content"),
}


def render_scan(result: ScanResult, console: Console | None = None) -> None:
    """Print a clean, grouped, colorized report of a scan."""
    console = console or Console()

    if not result.detections:
        console.print(
            f"[dim]No AI components found in {result.files_scanned} file(s) under[/dim] "
            f"{escape(str(result.root))}"
        )
        return

    # Align columns across the whole report so files read consistently.
    rule_w = max(len(d.rule_id) for d in result.detections)
    type_w = max(len(d.component_type.value) for d in result.detections)

    for path, dets in result.detections_by_file().items():
        console.print(f"\n[bold]{escape(_relativize(path, result.root))}[/bold]")
        for det in dets:
            console.print("  " + _render_row(det, rule_w, type_w))

    _render_summary(result, console)


def _render_row(det: Detection, rule_w: int, type_w: int) -> str:
    loc = f"{det.span.start_line}:{det.span.start_col + 1}"
    style = _TYPE_STYLE.get(det.component_type.value, "white")
    type_cell = f"{det.component_type.value:<{type_w}}"
    rule_cell = f"{det.rule_id:<{rule_w}}"
    evidence = escape(_truncate(det.evidence, _EVIDENCE_MAX))
    provider = f" [dim]({escape(det.provider)})[/dim]" if det.provider else ""
    return (
        f"[dim]{loc:>7}[/dim]  [{style}]{type_cell}[/{style}]  "
        f"[bold]{rule_cell}[/bold]  {evidence}{provider}"
    )


def _render_summary(result: ScanResult, console: Console) -> None:
    console.print(
        f"\n[bold]Summary:[/bold] {len(result.detections)} detection(s) across "
        f"{result.files_with_findings} of {result.files_scanned} file(s) scanned."
    )
    by_type = result.counts_by_component_type()
    if by_type:
        parts = "   ".join(f"[bold]{k}[/bold]: {v}" for k, v in by_type.items())
        console.print(f"  {parts}")


def render_enrichment(report: EnrichmentReport, console: Console | None = None) -> None:
    """Print licenses, CVEs, and honest provenance gaps for enriched findings."""
    console = console or Console()
    if not report.packages and not report.models:
        return

    if report.offline:
        console.print("\n[dim](offline mode - served from cache where available)[/dim]")

    if report.packages:
        console.print("\n[bold]Packages[/bold]")
        for pkg in report.packages.values():
            console.print("  " + _render_package(pkg))

    if report.models:
        console.print("\n[bold]Models[/bold]")
        for model in report.models.values():
            for line in _render_model(model):
                console.print("  " + line)

    console.print(
        f"\n[bold]Enrichment:[/bold] {len(report.packages)} package(s), "
        f"{len(report.models)} model(s), {report.total_vulns} known vuln(s)."
    )


def _render_package(pkg: EnrichedPackage) -> str:
    version = f"[dim]{escape(pkg.pypi.version)}[/dim]" if pkg.pypi.version else "[dim]?[/dim]"
    license_ = escape(pkg.pypi.license) if pkg.pypi.license else "[yellow]license unknown[/yellow]"
    if pkg.vulns:
        ids = ", ".join(escape(v.id) for v in pkg.vulns[:3])
        more = f" +{len(pkg.vulns) - 3} more" if len(pkg.vulns) > 3 else ""
        vulns = f"[red]{len(pkg.vulns)} CVE(s)[/red] ({ids}{more})"
    else:
        vulns = "[green]no known CVEs[/green]"
    return f"[bold]{escape(pkg.name)}[/bold] {version}  {license_}  {vulns}"


def _render_model(model: EnrichedModel) -> list[str]:
    hf = model.hf
    lic = escape(hf.license) if hf.license else "[yellow]license undeclared[/yellow]"
    head = f"[bold]{escape(model.repo_id)}[/bold]  {lic}"
    if hf.base_model:
        head += f"  [dim]base: {escape(hf.base_model)}[/dim]"
    # Honest gaps: never a green check for something no scanner can verify.
    gaps = (
        f"    [yellow]provenance: {model.provenance}[/yellow]   "
        f"[yellow]consent_basis: {model.consent_basis}[/yellow]  "
        f"[dim](needs attestation)[/dim]"
    )
    return [head, gaps]


def render_policy(report: PolicyReport, console: Console | None = None) -> None:
    """Print obligations grouped by status, with derivable vs attestation gaps marked."""
    console = console or Console()
    if not report.obligations:
        console.print("[dim]No EU AI Act obligations triggered by detected components.[/dim]")
        return

    if report.applies:
        console.print("[bold]Obligations (apply)[/bold]")
        for ob in report.applies:
            for line in _render_obligation(ob):
                console.print(line)

    if report.potential:
        console.print("\n[bold]Obligations (may apply - declare project facts)[/bold]")
        for ob in report.potential:
            for line in _render_obligation(ob):
                console.print(line)

    n_gaps = len(report.gaps)
    console.print(
        f"\n[bold]Policy:[/bold] {len(report.applies)} applies, "
        f"{len(report.potential)} potential, "
        f"[yellow]{n_gaps} gap(s) needing attestation[/yellow]."
    )


def _render_obligation(ob: Obligation) -> list[str]:
    badge = (
        "[red]APPLIES[/red]" if ob.status is ObligationStatus.APPLIES else "[yellow]MAYBE[/yellow]"
    )
    verify = (
        "[yellow]requires attestation[/yellow]" if ob.is_gap else "[green]auto-verifiable[/green]"
    )
    lines = [
        f"\n  {badge}  [bold]{escape(ob.citation)}[/bold] {escape(ob.title)}  ({verify})",
        f"    {escape(ob.obligation.strip())}",
        f"    [dim]triggered by: {escape(', '.join(ob.components))}[/dim]",
    ]
    if ob.unresolved:
        keys = ", ".join(ob.unresolved)
        yes, no = _PROJECT_FLAGS.get(ob.unresolved[0], ("", ""))
        hint = f" [dim](declare with {yes} / {no})[/dim]" if yes else ""
        lines.append(f"    [yellow]unresolved:[/yellow] {escape(keys)}{hint}")
    return lines


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _relativize(path: str, root: os.PathLike[str]) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:  # different drive on Windows
        return path


def scan_to_dict(result: ScanResult) -> dict[str, Any]:
    """Serialize a scan result to a plain dict for ``--json`` output."""
    return {
        "root": str(result.root),
        "files_scanned": result.files_scanned,
        "files_with_findings": result.files_with_findings,
        "summary": {
            "by_component_type": result.counts_by_component_type(),
            "by_provider": result.counts_by_provider(),
        },
        "detections": [_detection_to_dict(d) for d in result.detections],
    }


def _detection_to_dict(det: Detection) -> dict[str, Any]:
    return {
        "rule_id": det.rule_id,
        "name": det.name,
        "component_type": det.component_type.value,
        "provider": det.provider,
        "match_kind": det.match_kind,
        "evidence": det.evidence,
        "path": det.path,
        "line": det.span.start_line,
        "column": det.span.start_col,
        "end_line": det.span.end_line,
        "end_column": det.span.end_col,
        "tags": list(det.tags),
    }


def enrichment_to_dict(report: EnrichmentReport) -> dict[str, Any]:
    """Serialize an enrichment report to a plain dict for ``--json`` output."""
    return {
        "offline": report.offline,
        "total_vulns": report.total_vulns,
        "packages": {
            name: {
                "name": pkg.name,
                "status": pkg.pypi.status.value,
                "version": pkg.pypi.version,
                "license": pkg.pypi.license,
                "vulns_status": pkg.vulns_status.value,
                "vulns": [
                    {
                        "id": v.id,
                        "aliases": list(v.aliases),
                        "summary": v.summary,
                        "severity": v.severity,
                    }
                    for v in pkg.vulns
                ],
            }
            for name, pkg in report.packages.items()
        },
        "models": {
            repo_id: {
                "repo_id": model.repo_id,
                "status": model.hf.status.value,
                "license": model.hf.license,
                "base_model": model.hf.base_model,
                "datasets": list(model.hf.datasets),
                "provenance": model.provenance,
                "consent_basis": model.consent_basis,
            }
            for repo_id, model in report.models.items()
        },
    }


def policy_to_dict(report: PolicyReport) -> dict[str, Any]:
    """Serialize a policy report to a plain dict for ``--json`` output."""
    return {
        "summary": {
            "applies": len(report.applies),
            "potential": len(report.potential),
            "gaps": len(report.gaps),
        },
        "obligations": [
            {
                "rule_id": ob.rule_id,
                "regulation": ob.regulation,
                "citation": ob.citation,
                "title": ob.title,
                "obligation": ob.obligation.strip(),
                "verification": ob.verification.value,
                "severity": ob.severity.value,
                "status": ob.status.value,
                "is_gap": ob.is_gap,
                "components": list(ob.components),
                "unresolved": list(ob.unresolved),
                "references": list(ob.references),
            }
            for ob in report.obligations
        ],
    }
