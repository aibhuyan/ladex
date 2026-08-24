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

from ladex import __version__
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
            "usage: ladex scan [PATH] [--json] [--enrich] [--offline] [--hf-token TOKEN]",
            file=sys.stderr,
        )
        return 0
    as_json = "--json" in args
    do_enrich = "--enrich" in args or "--offline" in args
    offline = "--offline" in args
    hf_token = _flag_value(args, "--hf-token") or os.environ.get("HF_TOKEN")
    positional = [a for a in args if not a.startswith("-")]
    # Drop a value consumed by --hf-token from positionals.
    if hf_token and hf_token in positional:
        positional.remove(hf_token)
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


def _detect_command(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        print("usage: ladex detect FILE.py", file=sys.stderr)
        return 0 if args else 2
    target = Path(args[0])
    if not target.is_file():
        print(f"not a file: {target}", file=sys.stderr)
        return 2
    detections = PythonDetector().detect_file(target)
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
