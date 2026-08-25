"""Obligation-level attestation: a signed 'satisfied' closes an obligation gate."""

from __future__ import annotations

import json
from pathlib import Path

from ladex.engine.attest import (
    OBLIGATION_CLAIM,
    AttestationStore,
    LocalSigner,
    create_attestation,
)
from ladex.engine.bom import build_bom, render_json
from ladex.engine.ci import build_ci_report
from ladex.engine.policy import ProjectContext, find_obligation_rule, rule_fingerprint
from ladex.engine.scan import scan_path

RULE = "art-50-1-ai-interaction-disclosure"


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("import openai\nopenai.OpenAI()\n", encoding="utf-8")
    return tmp_path


def _rule_hash(rule_id: str) -> str:
    rule = find_obligation_rule(rule_id)
    assert rule is not None
    return rule_fingerprint(rule)


def test_applicable_obligation_is_a_gap_until_attested(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = build_ci_report(repo, ProjectContext(user_facing=True))
    assert any(g.kind == "obligation" and g.subject == RULE for g in before.gaps)
    assert before.passed is False


def test_obligation_attestation_closes_the_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    signer = LocalSigner(key_path=tmp_path / "key")
    AttestationStore.for_root(repo).add(
        create_attestation(
            RULE,
            OBLIGATION_CLAIM,
            "UI shows an 'AI assistant' banner on all entry points",
            "compliance@company.com",
            signer,
            bindings={"rule_hash": _rule_hash(RULE)},
        )
    )
    report = build_ci_report(repo, ProjectContext(user_facing=True))
    assert all(g.subject != RULE for g in report.gaps)  # obligation gap closed
    assert report.passed is True  # no gaps left (no loadable models here)


def test_stale_sign_off_reopens_the_gate(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    signer = LocalSigner(key_path=tmp_path / "key")
    # Attest against a DIFFERENT rule hash (as if the rule text had since changed).
    AttestationStore.for_root(repo).add(
        create_attestation(
            RULE,
            OBLIGATION_CLAIM,
            "implemented",
            "compliance@company.com",
            signer,
            bindings={"rule_hash": "deadbeefdeadbeef"},
        )
    )
    report = build_ci_report(repo, ProjectContext(user_facing=True))
    gap = next(g for g in report.gaps if g.subject == RULE)
    assert "stale" in gap.summary.lower()  # re-opened
    assert report.passed is False


def test_remedy_is_the_attest_command(tmp_path: Path) -> None:
    report = build_ci_report(_repo(tmp_path), ProjectContext(user_facing=True))
    gap = next(g for g in report.gaps if g.subject == RULE)
    assert gap.remedy.startswith(f"ladex attest {RULE} --claim satisfied")


def test_bom_records_obligation_attester(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    signer = LocalSigner(key_path=tmp_path / "key")
    att = create_attestation(
        RULE, OBLIGATION_CLAIM, "implemented", "compliance@company.com", signer
    )
    from ladex.engine.policy import check_scan

    result = scan_path(repo)
    policy = check_scan(result, ProjectContext(user_facing=True))
    doc = json.loads(
        render_json(build_bom(result, policy=policy, attestations=[att], project_name="p"))
    )
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props.get(f"ladex:obligation:{RULE}.attested_by") == "compliance@company.com"
