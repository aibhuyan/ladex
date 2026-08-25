"""Ladex command-line interface.

Kept intentionally dependency-free (stdlib ``argparse``) until Step 3, when ``ladex scan``
and a richer CLI (typer/rich) land. For now it exposes taxonomy inspection so Step 1 is
runnable and verifiable:

    ladex --version
    ladex scan [PATH] [--json]
    ladex taxonomy validate [PACK.yaml ...]
    ladex taxonomy list
    ladex detect FILE.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ladex import __version__

if TYPE_CHECKING:
    from ladex.engine.policy import ProjectContext
from ladex.engine.detect import PythonDetector
from ladex.engine.scan import scan_path
from ladex.engine.taxonomy import (
    AttributeMatch,
    CallMatch,
    ImportMatch,
    Rule,
    StringMatch,
    TaxonomyError,
    aggregate,
    load_builtin_packs,
    load_pack_file,
)

_VERSION_FLAGS = {"--version", "-V", "version"}


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``ladex`` console script."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        _print_banner()
        return 0
    if args[0] in _VERSION_FLAGS:
        print(f"ladex {__version__}")
        return 0
    if args[0] == "scan":
        return _scan_command(args[1:])
    if args[0] == "policy":
        return _policy_command(args[1:])
    if args[0] == "ci":
        return _ci_command(args[1:])
    if args[0] == "attest":
        return _attest_command(args[1:])
    if args[0] == "verify":
        return _verify_command(args[1:])
    if args[0] == "serve":
        return _serve_command(args[1:])
    if args[0] == "taxonomy":
        return _taxonomy_command(args[1:])
    if args[0] == "detect":
        return _detect_command(args[1:])
    print(f"ladex {__version__} - a bill of lading for AI")
    print(f"unknown command: {args[0]!r}. Try 'ladex taxonomy list'.", file=sys.stderr)
    return 2


def _print_banner() -> None:
    print(f"ladex {__version__} - a bill of lading for AI")
    print("Commands: `ladex scan [PATH]`, `ladex detect FILE`, `ladex taxonomy list`.")


def _scan_command(args: list[str]) -> int:
    if args and args[0] in {"-h", "--help"}:
        print(
            "usage: ladex scan [PATH] [--json] [--enrich] [--offline] [--hf-token TOKEN]\n"
            "                  [--write-bom [FILE]]",
            file=sys.stderr,
        )
        return 0
    as_json = "--json" in args
    write_bom = "--write-bom" in args
    do_enrich = "--enrich" in args or "--offline" in args
    offline = "--offline" in args
    hf_token = _flag_value(args, "--hf-token") or os.environ.get("HF_TOKEN")
    bom_path = Path(_flag_value(args, "--write-bom") or "aibom.cdx.json")
    consumed = {v for v in (hf_token, str(bom_path)) if v}
    positional = [a for a in args if not a.startswith("-") and a not in consumed]
    root = Path(positional[0]) if positional else Path(".")
    if not root.exists():
        print(f"path does not exist: {root}", file=sys.stderr)
        return 2

    # Import rendering lazily so `--json` needs no rich formatting path.
    from ladex.cli.report import (
        enrichment_to_dict,
        render_enrichment,
        render_scan,
        scan_to_dict,
    )

    result = scan_path(root)
    enrichment = None
    if do_enrich:
        from ladex.engine.enrich import enrich_scan

        enrichment = enrich_scan(result, offline=offline, hf_token=hf_token)

    if write_bom:
        from ladex.engine.attest import AttestationStore
        from ladex.engine.bom import build_bom, render_json
        from ladex.engine.policy import check_scan

        policy = check_scan(result)
        attestations = AttestationStore.for_root(root).load()
        bom = build_bom(result, enrichment=enrichment, policy=policy, attestations=attestations)
        bom_path.write_text(render_json(bom), encoding="utf-8")
        print(f"wrote {bom_path} ({len(result.detections)} detection(s))")
        return 0

    if as_json:
        payload = scan_to_dict(result)
        if enrichment is not None:
            payload["enrichment"] = enrichment_to_dict(enrichment)
        print(json.dumps(payload, indent=2))
    else:
        render_scan(result)
        if enrichment is not None:
            render_enrichment(enrichment)
    # `scan` is informational: presence of AI is not a failure. Gating on obligations
    # and gaps is the policy layer's job (Step 5).
    return 0


def _flag_value(args: list[str], flag: str) -> str | None:
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1]
    return None


def _tristate(args: list[str], yes: str, no: str) -> bool | None:
    if yes in args:
        return True
    if no in args:
        return False
    return None


def _policy_command(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        print(
            "usage: ladex policy {check|list|init} [PATH] [--json]\n"
            "  init  writes .ladex/project.yaml (declare EU AI Act classification)\n"
            "  project facts: --user-facing/--not-user-facing, "
            "--synthetic-content/--no-synthetic-content (or the profile file)",
            file=sys.stderr,
        )
        return 0 if args else 2
    sub, rest = args[0], args[1:]
    if sub == "list":
        return _policy_list()
    if sub == "check":
        return _policy_check(rest)
    if sub == "init":
        return _policy_init(rest)
    print(f"unknown policy subcommand: {sub!r}", file=sys.stderr)
    return 2


def _policy_init(args: list[str]) -> int:
    from ladex.engine.policy import PROJECT_FILE, project_template

    positional = [a for a in args if not a.startswith("-")]
    root = Path(positional[0]) if positional else Path(".")
    target = root / PROJECT_FILE
    if target.exists():
        print(f"{target} already exists — leaving it untouched.", file=sys.stderr)
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(project_template(), encoding="utf-8")
    print(f"wrote {target}\nEdit it to declare your EU AI Act classification, then commit it.")
    return 0


def _project_from(root: Path, args: list[str]) -> ProjectContext | None:
    """Load .ladex/project.yaml, then let CLI flags override declared facts."""
    from ladex.engine.policy import ProjectContext, ProjectContextError, load_project_context

    overrides = ProjectContext(
        user_facing=_tristate(args, "--user-facing", "--not-user-facing"),
        generates_synthetic_content=_tristate(
            args, "--synthetic-content", "--no-synthetic-content"
        ),
    )
    try:
        base = load_project_context(root)
    except ProjectContextError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return None
    return base.merge(overrides)


def _policy_list() -> int:
    from ladex.engine.policy import PolicyError, load_builtin_bundles

    try:
        bundles = load_builtin_bundles()
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    for bundle in bundles:
        print(f"{bundle.id} ({bundle.regulation}) v{bundle.version}: {len(bundle.rules)} rule(s)")
        for rule in bundle.rules:
            print(f"  - {rule.citation:<10} {rule.id}  [{rule.verification.value}]")
    return 0


def _policy_check(args: list[str]) -> int:
    from ladex.cli.report import policy_to_dict, render_policy
    from ladex.engine.policy import PolicyError, ProjectContext, check_scan

    as_json = "--json" in args
    positional = [a for a in args if not a.startswith("-")]
    root = Path(positional[0]) if positional else Path(".")
    if not root.exists():
        print(f"path does not exist: {root}", file=sys.stderr)
        return 2

    project = _project_from(root, args)
    if project is None:
        return 1
    assert isinstance(project, ProjectContext)

    try:
        result = scan_path(root)
        report = check_scan(result, project)
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps(policy_to_dict(report), indent=2))
    else:
        render_policy(report)
    # Informational for now; the CI gate on open gaps turns on with attestation (Step 7).
    return 0


def _ci_command(args: list[str]) -> int:
    if args and args[0] in {"-h", "--help"}:
        print(
            "usage: ladex ci [PATH] [--format text|markdown|json|github]\n"
            "                [--fail-on none|gaps|strict]\n"
            "                [--user-facing/--not-user-facing] "
            "[--synthetic-content/--no-synthetic-content]",
            file=sys.stderr,
        )
        return 0

    import os as _os

    from ladex.cli.report import (
        ci_to_dict,
        emit_github_annotations,
        render_ci,
    )
    from ladex.engine.ci import FailOn, build_ci_report, render_markdown
    from ladex.engine.policy import ProjectContext

    fmt = _flag_value(args, "--format") or "text"
    fail_on_raw = _flag_value(args, "--fail-on") or "gaps"
    try:
        fail_on = FailOn(fail_on_raw)
    except ValueError:
        print(f"invalid --fail-on {fail_on_raw!r}; choose none|gaps|strict", file=sys.stderr)
        return 2

    consumed = {v for v in (fmt, fail_on_raw) if v}
    positional = [a for a in args if not a.startswith("-") and a not in consumed]
    root = Path(positional[0]) if positional else Path(".")
    if not root.exists():
        print(f"path does not exist: {root}", file=sys.stderr)
        return 2

    project = _project_from(root, args)
    if project is None:
        return 1
    assert isinstance(project, ProjectContext)

    report = build_ci_report(root, project, fail_on=fail_on)

    if fmt == "json":
        print(json.dumps(ci_to_dict(report), indent=2))
    elif fmt == "markdown":
        print(render_markdown(report), end="")
    elif fmt == "github":
        # Inline annotations + a job summary when running inside GitHub Actions.
        emit_github_annotations(report)
        summary_path = _os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(render_markdown(report))
    else:
        render_ci(report)

    return 0 if report.passed else 1


def _attest_command(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        print(
            "usage: ladex attest SUBJECT --claim CLAIM --value TEXT [--attester WHO] [--path DIR]\n"
            "  SUBJECT + CLAIM:\n"
            "    a model id (e.g. sentence-transformers/all-MiniLM-L6-v2): "
            "--claim provenance|consent_basis\n"
            "    an obligation rule id (e.g. art-50-1-ai-interaction-disclosure): "
            "--claim satisfied",
            file=sys.stderr,
        )
        return 0 if args else 2

    from ladex.engine.attest import (
        ALL_CLAIMS,
        AttestationStore,
        create_attestation,
        get_signer,
    )

    positional = [a for a in args if not a.startswith("-")]
    consumed = {
        v
        for v in (
            _flag_value(args, "--claim"),
            _flag_value(args, "--value"),
            _flag_value(args, "--attester"),
            _flag_value(args, "--path"),
        )
        if v
    }
    positional = [p for p in positional if p not in consumed]
    if not positional:
        print("attest requires a SUBJECT (a model id or an obligation rule id)", file=sys.stderr)
        return 2
    subject = positional[0]
    claim = _flag_value(args, "--claim") or "provenance"
    if claim not in ALL_CLAIMS:
        print(f"unknown claim {claim!r}; choose from {list(ALL_CLAIMS)}", file=sys.stderr)
        return 2
    value = _flag_value(args, "--value")
    if value is None:
        print("attest requires --value (the declaration text)", file=sys.stderr)
        return 2
    attester = _flag_value(args, "--attester") or _git_email() or "unknown"
    root = Path(_flag_value(args, "--path") or ".")

    from ladex.engine.attest import OBLIGATION_CLAIM

    # Bind an obligation sign-off to the exact rule text, so a later rule change re-opens it.
    bindings: dict[str, str] = {}
    if claim == OBLIGATION_CLAIM:
        from ladex.engine.policy import find_obligation_rule, rule_fingerprint

        rule = find_obligation_rule(subject)
        if rule is None:
            print(f"warning: no obligation rule {subject!r} found; attesting without a binding")
        else:
            bindings["rule_hash"] = rule_fingerprint(rule)

    signer = get_signer("local")
    attestation = create_attestation(subject, claim, value, attester, signer, bindings=bindings)
    AttestationStore.for_root(root).add(attestation)
    print(
        f"attested {claim} for {subject}\n"
        f"  signed by {attester} (keyid {attestation.keyid}, {signer.__class__.__name__})\n"
        f"  stored in {root / '.ladex' / 'attestations.json'}"
    )
    return 0


def _verify_command(args: list[str]) -> int:
    if args and args[0] in {"-h", "--help"}:
        print("usage: ladex verify [PATH]", file=sys.stderr)
        return 0

    from ladex.engine.attest import AttestationStore, verify_attestation

    positional = [a for a in args if not a.startswith("-")]
    root = Path(positional[0]) if positional else Path(".")
    attestations = AttestationStore.for_root(root).load()
    if not attestations:
        print("no attestations found.")
        return 0

    ok = 0
    for att in attestations:
        valid = verify_attestation(att)
        ok += valid
        mark = "OK  " if valid else "FAIL"
        print(f"  [{mark}] {att.subject}  {att.claim}  <- {att.attester}")
    bad = len(attestations) - ok
    print(f"\n{ok} valid, {bad} invalid attestation(s).")
    return 0 if bad == 0 else 1


def _serve_command(args: list[str]) -> int:
    if args and args[0] in {"-h", "--help"}:
        print("usage: ladex serve   (runs the LSP server over stdio)", file=sys.stderr)
        return 0
    from ladex.engine.server import start_stdio

    start_stdio()
    return 0


def _git_email() -> str | None:
    import subprocess

    try:
        out = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    email = out.stdout.strip()
    return email or None


def _detect_command(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        print("usage: ladex detect FILE.py|FILE.ipynb", file=sys.stderr)
        return 0 if args else 2
    target = Path(args[0])
    if not target.is_file():
        print(f"not a file: {target}", file=sys.stderr)
        return 2
    detector = PythonDetector()
    if target.suffix == ".ipynb":
        from ladex.engine.detect.notebook import detect_notebook_file

        detections = detect_notebook_file(target, detector)
    else:
        detections = detector.detect_file(target)
    if not detections:
        return 0  # ruthless silence: nothing AI-relevant, say nothing
    for d in detections:
        print(f"{d.location():<28} {d.component_type.value:<15} {d.rule_id:<28} {d.evidence}")
    print(f"\n{len(detections)} detection(s).")
    return 0


def _taxonomy_command(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        print("usage: ladex taxonomy {validate|list} [PACK.yaml ...]", file=sys.stderr)
        return 0 if args else 2
    sub, rest = args[0], args[1:]
    if sub == "validate":
        return _taxonomy_validate([Path(p) for p in rest])
    if sub == "list":
        return _taxonomy_list()
    print(f"unknown taxonomy subcommand: {sub!r}", file=sys.stderr)
    return 2


def _taxonomy_validate(extra_paths: list[Path]) -> int:
    try:
        packs = load_builtin_packs()
        packs.extend(load_pack_file(p) for p in extra_paths)
        taxonomy = aggregate(packs)
    except TaxonomyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {len(taxonomy.packs)} pack(s), {len(taxonomy)} rule(s) validated.")
    for pack in taxonomy.packs:
        print(f"  - {pack.name} v{pack.version}: {len(pack.rules)} rule(s)")
    return 0


def _taxonomy_list() -> int:
    try:
        taxonomy = aggregate(load_builtin_packs())
    except TaxonomyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    rules = sorted(taxonomy.rules, key=lambda r: (r.component_type.value, r.id))
    width = max((len(r.id) for r in rules), default=3)
    for rule in rules:
        print(f"{rule.id:<{width}}  {rule.component_type.value:<15}  {_match_summary(rule)}")
    print(f"\n{len(rules)} rule(s).")
    return 0


def _match_summary(rule: Rule) -> str:
    m = rule.match
    if isinstance(m, ImportMatch):
        return f"import {m.module}" + (f".{m.symbol}" if m.symbol else "")
    if isinstance(m, CallMatch):
        return f"call {m.target}()"
    if isinstance(m, AttributeMatch):
        return f"attr {m.target}"
    if isinstance(m, StringMatch):
        return f"string /{m.pattern}/"
    return "?"  # pragma: no cover - exhaustive above


if __name__ == "__main__":
    raise SystemExit(main())
