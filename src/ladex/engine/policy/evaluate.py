"""The policy evaluator: (component facts + project context + bundles) -> obligations.

For each rule it finds the components whose signals match, then tests the rule's project
conditions against the declared context:

- a required project fact that is **False** suppresses the rule (it genuinely doesn't apply);
- a required fact that is **unknown** yields POTENTIALLY_APPLIES, naming the undeclared fact;
- all facts satisfied yields APPLIES.

A rule that matches no component produces nothing — ruthless silence extends to obligations.
One obligation is emitted per rule, listing every component that triggered it, so two
providers don't produce two identical duties.
"""

from __future__ import annotations

from collections.abc import Iterable

from ladex.engine.policy.context import ComponentFact, ProjectContext
from ladex.engine.policy.models import AppliesWhen, PolicyBundle, PolicyRule
from ladex.engine.policy.report import Obligation, ObligationStatus, PolicyReport


def evaluate(
    facts: Iterable[ComponentFact],
    project: ProjectContext,
    bundles: Iterable[PolicyBundle],
) -> PolicyReport:
    fact_list = list(facts)
    obligations: list[Obligation] = []
    for bundle in bundles:
        for rule in bundle.rules:
            obligation = _evaluate_rule(rule, bundle.regulation, fact_list, project)
            if obligation is not None:
                obligations.append(obligation)
    obligations.sort(key=Obligation.sort_key)
    return PolicyReport(obligations=tuple(obligations))


def _evaluate_rule(
    rule: PolicyRule,
    regulation: str,
    facts: list[ComponentFact],
    project: ProjectContext,
) -> Obligation | None:
    matching = [f for f in facts if _component_matches(rule.applies_when, f)]
    if not matching:
        return None  # no relevant component -> no obligation

    status, unresolved = _project_status(rule.applies_when, project)
    if status is None:
        return None  # a required project fact is explicitly False -> rule suppressed

    return Obligation(
        rule_id=rule.id,
        regulation=regulation,
        title=rule.title,
        citation=rule.citation,
        obligation=rule.obligation,
        verification=rule.verification,
        severity=rule.severity,
        status=status,
        components=tuple(sorted(f.name for f in matching)),
        unresolved=unresolved,
        references=tuple(rule.references),
    )


def _component_matches(cond: AppliesWhen, fact: ComponentFact) -> bool:
    if cond.component_type and fact.component_type not in cond.component_type:
        return False
    if cond.provider is not None and cond.provider != fact.provider:
        return False
    tags = set(fact.tags)
    if cond.tags_any and tags.isdisjoint(cond.tags_any):
        return False
    return not (cond.tags_all and not set(cond.tags_all) <= tags)


def _project_status(
    cond: AppliesWhen, project: ProjectContext
) -> tuple[ObligationStatus, tuple[str, ...]] | tuple[None, tuple[str, ...]]:
    """Return (status, unresolved) or (None, ()) if the rule is suppressed."""
    unresolved: list[str] = []
    for key, required in cond.project.items():
        actual = project.get(key)
        if actual is None:
            unresolved.append(key)
        elif actual != required:
            return None, ()
    if unresolved:
        return ObligationStatus.POTENTIALLY_APPLIES, tuple(sorted(unresolved))
    return ObligationStatus.APPLIES, ()
