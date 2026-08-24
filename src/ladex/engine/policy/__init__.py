"""Policy: versioned EU AI Act obligation bundles + a pure-Python evaluator (★ IP)."""

from __future__ import annotations

from ladex.engine.policy.context import ComponentFact, ProjectContext, component_facts
from ladex.engine.policy.evaluate import evaluate
from ladex.engine.policy.loader import (
    PolicyError,
    load_builtin_bundles,
    load_bundle_file,
    parse_bundle,
)
from ladex.engine.policy.models import (
    AppliesWhen,
    PolicyBundle,
    PolicyRule,
    Severity,
    Verification,
)
from ladex.engine.policy.report import Obligation, ObligationStatus, PolicyReport
from ladex.engine.policy.service import check_scan

__all__ = [
    "AppliesWhen",
    "ComponentFact",
    "Obligation",
    "ObligationStatus",
    "PolicyBundle",
    "PolicyError",
    "PolicyReport",
    "PolicyRule",
    "ProjectContext",
    "Severity",
    "Verification",
    "check_scan",
    "component_facts",
    "evaluate",
    "load_bundle_file",
    "load_builtin_bundles",
    "parse_bundle",
]
