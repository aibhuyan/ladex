"""Policy evaluation: the three-way APPLIES / POTENTIALLY / silent behaviour."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.policy import (
    ProjectContext,
    check_scan,
    component_facts,
    evaluate,
)
from ladex.engine.policy.context import ComponentFact
from ladex.engine.policy.models import (
    AppliesWhen,
    PolicyBundle,
    PolicyRule,
    Verification,
)
from ladex.engine.policy.report import ObligationStatus
from ladex.engine.scan import scan_path
from ladex.engine.taxonomy.models import ComponentType

REPO = Path(__file__).parent.parent / "fixtures" / "sample_repo"


def _bundle() -> PolicyBundle:
    return PolicyBundle(
        schema_version=1,
        id="test",
        regulation="EU AI Act",
        version="0.1.0",
        rules=[
            PolicyRule(
                id="disclose",
                title="Disclose AI",
                citation="Art. 50(1)",
                obligation="Tell users they talk to an AI.",
                verification=Verification.REQUIRES_ATTESTATION,
                applies_when=AppliesWhen(
                    component_type=[ComponentType.INFERENCE_API],
                    project={"user_facing": True},
                ),
            )
        ],
    )


def _api_fact() -> ComponentFact:
    return ComponentFact(
        component_type=ComponentType.INFERENCE_API,
        provider="OpenAI",
        tags=("hosted",),
        source_rule_ids=("openai.client",),
    )


def test_applies_when_project_fact_true() -> None:
    report = evaluate([_api_fact()], ProjectContext(user_facing=True), [_bundle()])
    assert len(report.applies) == 1
    ob = report.applies[0]
    assert ob.status is ObligationStatus.APPLIES
    assert ob.is_gap  # requires attestation
    assert "OpenAI (inference_api)" in ob.components


def test_potential_when_project_fact_unknown() -> None:
    report = evaluate([_api_fact()], ProjectContext(), [_bundle()])  # user_facing unknown
    assert report.applies == ()
    assert len(report.potential) == 1
    assert report.potential[0].unresolved == ("user_facing",)


def test_suppressed_when_project_fact_false() -> None:
    report = evaluate([_api_fact()], ProjectContext(user_facing=False), [_bundle()])
    assert report.obligations == ()  # genuinely does not apply


def test_silent_when_no_matching_component() -> None:
    vector_fact = ComponentFact(
        component_type=ComponentType.VECTOR_STORE,
        provider="Pinecone",
        tags=(),
        source_rule_ids=("pinecone.client",),
    )
    report = evaluate([vector_fact], ProjectContext(user_facing=True), [_bundle()])
    assert report.obligations == ()  # ruthless silence extends to obligations


def test_one_obligation_lists_multiple_components() -> None:
    facts = [
        _api_fact(),
        ComponentFact(ComponentType.INFERENCE_API, "Anthropic", (), ("anthropic.client",)),
    ]
    report = evaluate(facts, ProjectContext(user_facing=True), [_bundle()])
    assert len(report.applies) == 1  # not two identical obligations
    assert len(report.applies[0].components) == 2


def test_component_facts_dedupe_detections() -> None:
    result = scan_path(REPO / "agents.py")
    facts = component_facts(result)
    signatures = {(f.component_type.value, f.provider) for f in facts}
    assert ("inference_api", "OpenAI") in signatures
    assert ("agent_framework", "LangChain") in signatures


def test_check_scan_end_to_end_potential() -> None:
    result = scan_path(REPO / "agents.py")
    report = check_scan(result, ProjectContext())  # nothing declared
    # OpenAI + Anthropic + LangChain are user-facing-capable -> Art 50(1) may apply.
    assert any(o.rule_id == "art-50-1-ai-interaction-disclosure" for o in report.potential)


def test_check_scan_end_to_end_applies() -> None:
    result = scan_path(REPO / "agents.py")
    report = check_scan(result, ProjectContext(user_facing=True))
    disclosure = next(
        o for o in report.applies if o.rule_id == "art-50-1-ai-interaction-disclosure"
    )
    assert disclosure.is_gap
    assert disclosure.citation == "Art. 50(1)"
