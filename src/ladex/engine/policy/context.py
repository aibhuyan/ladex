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
from pathlib import Path

import yaml

from ladex.engine.policy.models import ALLOWED_PROJECT_KEYS
from ladex.engine.scan import ScanResult
from ladex.engine.taxonomy.models import ComponentType

PROJECT_FILE = ".ladex/project.yaml"


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
    """Human-declared EU AI Act classification facts. ``None`` means 'not yet declared'.

    These cannot be derived from code, so a human declares them — typically once, in
    ``.ladex/project.yaml`` (see :func:`load_project_context`). Each is tri-state; an
    undeclared fact turns a conditional obligation into POTENTIALLY_APPLIES rather than
    silently assuming it away.
    """

    # transparency (Art. 50)
    user_facing: bool | None = None
    generates_synthetic_content: bool | None = None
    emotion_recognition: bool | None = None
    biometric_categorization: bool | None = None
    deepfakes: bool | None = None
    # risk classification
    high_risk: bool | None = None
    gpai_provider: bool | None = None
    # prohibited practices (Art. 5)
    social_scoring: bool | None = None
    manipulative_techniques: bool | None = None
    untargeted_facial_scraping: bool | None = None
    realtime_remote_biometric_id: bool | None = None

    def get(self, key: str) -> bool | None:
        if key not in ALLOWED_PROJECT_KEYS:
            raise KeyError(key)
        value = getattr(self, key)
        assert value is None or isinstance(value, bool)
        return value

    def merge(self, override: ProjectContext) -> ProjectContext:
        """Return a copy where any non-None field in ``override`` wins (CLI over file)."""
        values = {
            k: (getattr(override, k) if getattr(override, k) is not None else getattr(self, k))
            for k in ALLOWED_PROJECT_KEYS
        }
        return ProjectContext(**values)


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


class ProjectContextError(Exception):
    """Raised when ``.ladex/project.yaml`` is malformed."""


def load_project_context(root: Path) -> ProjectContext:
    """Load declared classification facts from ``<root>/.ladex/project.yaml`` (empty if absent)."""
    path = root / PROJECT_FILE
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ProjectContext()
    except (OSError, yaml.YAMLError) as exc:
        raise ProjectContextError(f"{path}: {exc}") from exc
    if raw is None:
        return ProjectContext()
    if not isinstance(raw, dict):
        raise ProjectContextError(f"{path}: top level must be a mapping")

    values: dict[str, bool | None] = {}
    for key, value in raw.items():
        if key == "version":
            continue
        if key not in ALLOWED_PROJECT_KEYS:
            raise ProjectContextError(
                f"{path}: unknown project fact {key!r}; allowed: {sorted(ALLOWED_PROJECT_KEYS)}"
            )
        if value is not None and not isinstance(value, bool):
            raise ProjectContextError(f"{path}: {key} must be true, false, or omitted")
        values[key] = value
    return ProjectContext(**values)


def project_template() -> str:
    """A commented ``.ladex/project.yaml`` template for ``ladex policy init``."""
    return (
        "# Ladex project profile — EU AI Act classification a human declares.\n"
        "# Each fact is true / false / omitted (omitted = undeclared -> 'may apply').\n"
        "version: 1\n\n"
        "# Transparency (Art. 50)\n"
        "# user_facing: true               # interacts directly with people -> 50(1)\n"
        "# generates_synthetic_content: false  # generative outputs -> 50(2)\n"
        "# emotion_recognition: false      # 50(3)\n"
        "# biometric_categorization: false # 50(3)\n"
        "# deepfakes: false                # 50(4)\n\n"
        "# Risk classification\n"
        "# high_risk: false        # an Annex III use case -> Art. 8-15 duties\n"
        "# gpai_provider: false     # you provide/train a general-purpose model -> Art. 53\n\n"
        "# Prohibited practices (Art. 5) - declaring true means STOP\n"
        "# social_scoring: false\n"
        "# manipulative_techniques: false\n"
        "# untargeted_facial_scraping: false\n"
        "# realtime_remote_biometric_id: false\n"
    )
