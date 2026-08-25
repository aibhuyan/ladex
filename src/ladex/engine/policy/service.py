"""Policy orchestration: evaluate a scan against the built-in bundles."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ladex.engine.policy.context import ProjectContext, component_facts
from ladex.engine.policy.evaluate import evaluate
from ladex.engine.policy.loader import load_builtin_bundles, load_project_bundles
from ladex.engine.policy.models import PolicyRule
from ladex.engine.policy.report import PolicyReport
from ladex.engine.scan import ScanResult


def check_scan(
    result: ScanResult, project: ProjectContext | None = None, *, root: Path | None = None
) -> PolicyReport:
    """Run the policy bundles over a scan result and project context.

    When ``root`` is given, the project's own bundles in ``.ladex/packs/policy`` are loaded
    alongside the built-ins.
    """
    facts = component_facts(result)
    bundles = load_project_bundles(root) if root is not None else load_builtin_bundles()
    return evaluate(facts, project or ProjectContext(), bundles)


def obligation_fingerprint(*, citation: str, title: str, obligation: str, verification: str) -> str:
    """A stable short hash of an obligation's *content* — an attestation binds to this so a
    materially changed rule re-opens a previously satisfied gate."""
    payload = "\x1f".join([citation, title, obligation.strip(), verification])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def rule_fingerprint(rule: PolicyRule) -> str:
    return obligation_fingerprint(
        citation=rule.citation,
        title=rule.title,
        obligation=rule.obligation,
        verification=rule.verification.value,
    )


def find_obligation_rule(rule_id: str, root: Path | None = None) -> PolicyRule | None:
    """Find a policy rule by id (for binding an obligation attestation to it).

    Searches the project's bundles (built-in + ``.ladex/packs/policy``) when ``root`` is given.
    """
    bundles = load_project_bundles(root) if root is not None else load_builtin_bundles()
    for bundle in bundles:
        for rule in bundle.rules:
            if rule.id == rule_id:
                return rule
    return None
