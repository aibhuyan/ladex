"""Policy orchestration: evaluate a scan against the built-in bundles."""

from __future__ import annotations

from ladex.engine.policy.context import ProjectContext, component_facts
from ladex.engine.policy.evaluate import evaluate
from ladex.engine.policy.loader import load_builtin_bundles
from ladex.engine.policy.report import PolicyReport
from ladex.engine.scan import ScanResult


def check_scan(result: ScanResult, project: ProjectContext | None = None) -> PolicyReport:
    """Run the built-in policy bundles over a scan result and project context."""
    facts = component_facts(result)
    bundles = load_builtin_bundles()
    return evaluate(facts, project or ProjectContext(), bundles)
