"""Inputs to policy evaluation: component facts and project context.

Detections are *occurrences*; policy reasons over *components*. `component_facts` collapses
a scan's detections into distinct logical components (one per component_type+provider),
which is the granularity obligations attach to.

Project context carries facts a scanner cannot derive from code — most importantly whether
the system is **user-facing**, the pivot for EU AI Act Art. 50. Each field is tri-state:
``True`` / ``False`` / ``None`` (unknown). ``None`` is not "no": an unknown user-facing flag
turns a disclosure obligation into POTENTIALLY_APPLIES, prompting the developer to declare
it, rather than silently assuming it away.
"""

from __future__ import annotations

from dataclasses import dataclass

from ladex.engine.policy.models import ALLOWED_PROJECT_KEYS
from ladex.engine.scan import ScanResult
from ladex.engine.taxonomy.models import ComponentType


@dataclass(frozen=True, slots=True)
class ComponentFact:
    """A distinct logical component that obligations attach to."""

    component_type: ComponentType
    provider: str | None
    tags: tuple[str, ...]
    source_rule_ids: tuple[str, ...]

    @property
    def name(self) -> str:
        base = self.provider or self.component_type.value
        return f"{base} ({self.component_type.value})"


@dataclass(frozen=True, slots=True)
class ProjectContext:
    """Human-supplied project facts. ``None`` means 'not yet declared'."""

    user_facing: bool | None = None
    generates_synthetic_content: bool | None = None

    def get(self, key: str) -> bool | None:
        if key not in ALLOWED_PROJECT_KEYS:
            raise KeyError(key)
        value = getattr(self, key)
        assert value is None or isinstance(value, bool)
        return value


def component_facts(result: ScanResult) -> tuple[ComponentFact, ...]:
    """Collapse a scan's detections into distinct (component_type, provider) components."""
    grouped: dict[tuple[ComponentType, str | None], dict[str, set[str]]] = {}
    for det in result.detections:
        key = (det.component_type, det.provider)
        bucket = grouped.setdefault(key, {"tags": set(), "rules": set()})
        bucket["tags"].update(det.tags)
        bucket["rules"].add(det.rule_id)
    facts = [
        ComponentFact(
            component_type=ctype,
            provider=provider,
            tags=tuple(sorted(bucket["tags"])),
            source_rule_ids=tuple(sorted(bucket["rules"])),
        )
        for (ctype, provider), bucket in grouped.items()
    ]
    facts.sort(key=lambda f: (f.component_type.value, f.provider or ""))
    return tuple(facts)
