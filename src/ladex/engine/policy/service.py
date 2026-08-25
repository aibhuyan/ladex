"""Policy orchestration: evaluate a scan against the built-in bundles."""

from __future__ import annotations

import hashlib

from ladex.engine.policy.context import ProjectContext, component_facts
from ladex.engine.policy.evaluate import evaluate
from ladex.engine.policy.loader import load_builtin_bundles
from ladex.engine.policy.models import PolicyRule
from ladex.engine.policy.report import PolicyReport
from ladex.engine.scan import ScanResult


def check_scan(result: ScanResult, project: ProjectContext | None = None) -> PolicyReport:
    """Run the built-in policy bundles over a scan result and project context."""
    facts = component_facts(result)
    bundles = load_builtin_bundles()
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


def find_obligation_rule(rule_id: str) -> PolicyRule | None:
    """Find a built-in policy rule by id (for binding an obligation attestation to it)."""
    for bundle in load_builtin_bundles():
        for rule in bundle.rules:
            if rule.id == rule_id:
                return rule
    return None
