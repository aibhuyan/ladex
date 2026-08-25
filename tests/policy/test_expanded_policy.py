"""Expanded EU AI Act coverage: Art. 5 bans, Annex III, Art. 53, Art. 50(3)/(4)."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.attest import (
    OBLIGATION_CLAIM,
    AttestationStore,
    LocalSigner,
    create_attestation,
)
from ladex.engine.ci import build_ci_report
from ladex.engine.policy import ProjectContext, check_scan, load_builtin_bundles
from ladex.engine.scan import scan_path


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("import openai\nopenai.OpenAI()\n", encoding="utf-8")
    return tmp_path


def test_all_bundles_load() -> None:
    ids = {b.id for b in load_builtin_bundles()}
    assert {
        "eu-ai-act-art-5",
        "eu-ai-act-art-50",
        "eu-ai-act-art-53",
        "eu-ai-act-annex-iii",
    } <= ids


def test_high_risk_triggers_seven_obligations(tmp_path: Path) -> None:
    result = scan_path(_repo(tmp_path))
    report = check_scan(result, ProjectContext(high_risk=True))
    annex3 = [o for o in report.applies if o.rule_id.startswith("annex3-")]
    assert len(annex3) == 7  # Art. 9-15


def test_gpai_provider_triggers_art53(tmp_path: Path) -> None:
    result = scan_path(_repo(tmp_path))
    report = check_scan(result, ProjectContext(gpai_provider=True))
    assert any(o.rule_id.startswith("art-53-") for o in report.applies)


def test_art50_3_and_4(tmp_path: Path) -> None:
    result = scan_path(_repo(tmp_path))
    ctx = ProjectContext(emotion_recognition=True, deepfakes=True)
    ids = {o.rule_id for o in check_scan(result, ctx).applies}
    assert "art-50-3-emotion-recognition-disclosure" in ids
    assert "art-50-4-deepfake-labeling" in ids


def test_prohibited_practice_is_a_hard_stop(tmp_path: Path) -> None:
    report = build_ci_report(_repo(tmp_path), ProjectContext(social_scoring=True))
    prohibited = [g for g in report.gaps if g.kind == "prohibited"]
    assert any(g.subject == "art-5-social-scoring" for g in prohibited)
    assert report.passed is False


def test_prohibited_cannot_be_attested_away(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    signer = LocalSigner(key_path=tmp_path / "key")
    # Even a signed "satisfied" attestation must NOT clear a prohibited-practice gate.
    AttestationStore.for_root(repo).add(
        create_attestation(
            "art-5-social-scoring", OBLIGATION_CLAIM, "we think it's fine", "x", signer
        )
    )
    report = build_ci_report(repo, ProjectContext(social_scoring=True))
    assert any(g.kind == "prohibited" for g in report.gaps)
    assert report.passed is False


def test_high_risk_obligations_close_on_attestation(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    signer = LocalSigner(key_path=tmp_path / "key")
    store = AttestationStore.for_root(repo)
    for rule in (
        "annex3-risk-management",
        "annex3-data-governance",
        "annex3-technical-documentation",
        "annex3-record-keeping",
        "annex3-transparency-to-deployers",
        "annex3-human-oversight",
        "annex3-accuracy-robustness-security",
    ):
        store.add(create_attestation(rule, OBLIGATION_CLAIM, "documented", "compliance@x", signer))
    report = build_ci_report(repo, ProjectContext(high_risk=True))
    assert all(g.kind != "obligation" for g in report.gaps)
    assert report.passed is True
