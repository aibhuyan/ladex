"""User-extensible packs: project-local taxonomy rules and policy bundles."""

from __future__ import annotations

from pathlib import Path

import pytest

from ladex.engine.policy import (
    PolicyError,
    ProjectContext,
    check_scan,
    load_project_bundles,
)
from ladex.engine.scan import scan_path
from ladex.engine.taxonomy import TaxonomyError, load_project_taxonomy

CUSTOM_TAXONOMY = """
schema_version: 1
name: acme-internal
version: 0.1.0
rules:
  - id: acme.internal-llm
    name: Acme internal LLM SDK
    component_type: inference_api
    provider: Acme
    match: { kind: import, module: acme_llm }
"""

CUSTOM_POLICY = """
schema_version: 1
id: acme-policy
regulation: Acme Internal
version: 0.1.0
rules:
  - id: acme.model-card-required
    title: Internal model card required
    citation: Acme-1
    obligation: Every inference API must have an internal model card.
    verification: requires_attestation
    severity: required
    applies_when:
      component_type: [inference_api]
"""


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_user_taxonomy_pack_is_loaded(tmp_path: Path) -> None:
    _write(tmp_path, ".ladex/packs/taxonomy/acme.yaml", CUSTOM_TAXONOMY)
    tax = load_project_taxonomy(tmp_path)
    assert tax.by_id("acme.internal-llm") is not None
    # built-ins still present
    assert tax.by_id("openai.import") is not None


def test_scan_uses_user_taxonomy(tmp_path: Path) -> None:
    _write(tmp_path, ".ladex/packs/taxonomy/acme.yaml", CUSTOM_TAXONOMY)
    _write(tmp_path, "app.py", "import acme_llm\n")
    result = scan_path(tmp_path)
    assert "acme.internal-llm" in {d.rule_id for d in result.detections}


def test_user_policy_bundle_is_evaluated(tmp_path: Path) -> None:
    _write(tmp_path, ".ladex/packs/policy/acme.yaml", CUSTOM_POLICY)
    _write(tmp_path, "app.py", "import openai\nopenai.OpenAI()\n")
    result = scan_path(tmp_path)
    report = check_scan(result, ProjectContext(), root=tmp_path)
    ids = {o.rule_id for o in report.applies}
    assert "acme.model-card-required" in ids  # custom rule fires
    assert "art-50-2-synthetic-content-marking" not in ids  # sanity: unrelated stays silent


def test_duplicate_rule_id_across_builtin_and_user_is_rejected(tmp_path: Path) -> None:
    clash = CUSTOM_TAXONOMY.replace("acme.internal-llm", "openai.import")
    _write(tmp_path, ".ladex/packs/taxonomy/clash.yaml", clash)
    with pytest.raises(TaxonomyError, match="duplicate rule id"):
        load_project_taxonomy(tmp_path)


def test_duplicate_policy_rule_id_rejected(tmp_path: Path) -> None:
    clash = CUSTOM_POLICY.replace("acme.model-card-required", "art-50-1-ai-interaction-disclosure")
    _write(tmp_path, ".ladex/packs/policy/clash.yaml", clash)
    with pytest.raises(PolicyError, match="duplicate policy rule id"):
        load_project_bundles(tmp_path)


def test_no_user_packs_is_just_builtins(tmp_path: Path) -> None:
    tax = load_project_taxonomy(tmp_path)
    assert tax.by_id("openai.import") is not None
    assert len(load_project_bundles(tmp_path)) >= 4
