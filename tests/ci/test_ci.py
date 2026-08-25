"""CI gate: gap detection, attestation coverage, fail-on levels, and Markdown."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.attest import AttestationStore, LocalSigner, create_attestation
from ladex.engine.ci import FailOn, build_ci_report, render_markdown
from ladex.engine.policy import ProjectContext

MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(
        f'import transformers\nEMBED = "{MODEL}"\nimport openai\nopenai.OpenAI()\n',
        encoding="utf-8",
    )
    return tmp_path


def test_unattested_model_is_a_provenance_gap(tmp_path: Path) -> None:
    report = build_ci_report(_repo(tmp_path), ProjectContext())
    subjects = {g.subject for g in report.provenance_gaps}
    assert MODEL in subjects
    # Both attestable claims are open.
    claims = {g.summary.split()[0] for g in report.provenance_gaps if g.subject == MODEL}
    assert "provenance" in claims and "consent" in claims


def test_hosted_model_names_are_not_gated(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('M = "gpt-4o"\nimport openai\n', encoding="utf-8")
    report = build_ci_report(tmp_path, ProjectContext())
    # gpt-4o is a hosted-API name, not loadable weights -> no provenance gap.
    assert all("gpt-4o" not in g.subject for g in report.provenance_gaps)


def test_attestation_closes_the_gap(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    signer = LocalSigner(key_path=tmp_path / "key")
    store = AttestationStore.for_root(repo)
    for claim in ("provenance", "consent_basis"):
        store.add(create_attestation(MODEL, claim, "public data", "me@org", signer))
    report = build_ci_report(repo, ProjectContext())
    assert all(g.subject != MODEL for g in report.provenance_gaps)


def test_applicable_obligation_is_a_gap_when_user_facing(tmp_path: Path) -> None:
    report = build_ci_report(_repo(tmp_path), ProjectContext(user_facing=True))
    assert any(g.kind == "obligation" and "50(1)" in (g.citation or "") for g in report.gaps)


def test_potential_obligation_is_a_warning_not_a_gap(tmp_path: Path) -> None:
    report = build_ci_report(_repo(tmp_path), ProjectContext())  # user_facing unknown
    assert any("50(1)" in w for w in report.warnings)


def test_fail_on_levels(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    assert build_ci_report(repo, ProjectContext(), fail_on=FailOn.NONE).passed is True
    # There are provenance gaps -> gaps/strict fail.
    assert build_ci_report(repo, ProjectContext(), fail_on=FailOn.GAPS).passed is False
    assert build_ci_report(repo, ProjectContext(), fail_on=FailOn.STRICT).passed is False


def test_strict_fails_on_warnings_only(tmp_path: Path) -> None:
    # A repo whose only issue is a *potential* obligation (no loadable models).
    (tmp_path / "a.py").write_text("import openai\nopenai.OpenAI()\n", encoding="utf-8")
    gaps = build_ci_report(tmp_path, ProjectContext(), fail_on=FailOn.GAPS)
    strict = build_ci_report(tmp_path, ProjectContext(), fail_on=FailOn.STRICT)
    assert gaps.gaps == ()  # no action-required gaps
    assert gaps.passed is True  # gaps-level passes
    assert strict.warnings  # but there's a potential obligation
    assert strict.passed is False  # strict fails on it


def test_clean_repo_passes(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    report = build_ci_report(tmp_path, ProjectContext(), fail_on=FailOn.STRICT)
    assert report.passed is True
    assert report.gaps == ()


def test_markdown_renders_verdict_and_gaps(tmp_path: Path) -> None:
    md = render_markdown(build_ci_report(_repo(tmp_path), ProjectContext()))
    assert "Ladex" in md
    assert "ACTION REQUIRED" in md
    assert MODEL in md
    assert "ladex attest" in md
