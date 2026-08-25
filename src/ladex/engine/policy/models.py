"""Policy bundle format and evaluation result types (★ IP).

Policy is **versioned data, not code**: a bundle is a YAML document of rules, loaded and
validated at runtime exactly like a taxonomy pack, so obligations can be updated without
shipping a new binary. A rule maps a set of conditions (on detected components and on
project context) to an *obligation*, and declares whether compliance is **derivable** by a
tool or **requires a human attestation** — the honest-gaps principle applied to duties.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ladex.engine.taxonomy.models import ComponentType

_ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")

#: Project-context fields a rule may condition on. Kept in sync with ProjectContext.
#: All are tri-state booleans (True / False / None=undeclared); a human declares them, since
#: EU AI Act classification cannot be derived from code.
ALLOWED_PROJECT_KEYS: frozenset[str] = frozenset(
    {
        # transparency (Art. 50)
        "user_facing",
        "generates_synthetic_content",
        "emotion_recognition",
        "biometric_categorization",
        "deepfakes",
        # risk classification
        "high_risk",  # Annex III use case
        "gpai_provider",  # provides/trains a general-purpose AI model (Art. 53)
        # prohibited practices (Art. 5)
        "social_scoring",
        "manipulative_techniques",
        "untargeted_facial_scraping",
        "realtime_remote_biometric_id",
    }
)

CURRENT_POLICY_SCHEMA_VERSION = 1


class Verification(StrEnum):
    """Whether an obligation's satisfaction can be checked by a tool or needs a human."""

    DERIVABLE = "derivable"  # a scanner can confirm this (e.g. a license, a CVE scan)
    REQUIRES_ATTESTATION = "requires_attestation"  # only a signed human answer can


class Severity(StrEnum):
    INFO = "info"
    ADVISORY = "advisory"
    REQUIRED = "required"
    PROHIBITED = "prohibited"  # Art. 5 bans — cannot be attested away


class AppliesWhen(BaseModel):
    """Conditions under which a rule's obligation is triggered."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    component_type: list[ComponentType] = Field(
        default_factory=list, description="Any-of; empty means any component present."
    )
    provider: str | None = None
    tags_any: list[str] = Field(default_factory=list)
    tags_all: list[str] = Field(default_factory=list)
    project: dict[str, bool] = Field(
        default_factory=dict, description="Required project-context facts."
    )

    @field_validator("project")
    @classmethod
    def _known_project_keys(cls, value: dict[str, bool]) -> dict[str, bool]:
        unknown = set(value) - ALLOWED_PROJECT_KEYS
        if unknown:
            raise ValueError(
                f"unknown project condition key(s): {sorted(unknown)}; "
                f"allowed: {sorted(ALLOWED_PROJECT_KEYS)}"
            )
        return value


class PolicyRule(BaseModel):
    """One obligation and the conditions that trigger it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    title: str = Field(min_length=1)
    citation: str = Field(min_length=1, description="Legal citation, e.g. 'Art. 50(1)'.")
    obligation: str = Field(min_length=1, description="What the developer must do.")
    verification: Verification
    applies_when: AppliesWhen
    severity: Severity = Severity.ADVISORY
    references: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_well_formed(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(f"rule id {value!r} must be lowercase dotted/dashed segments")
        return value


class PolicyBundle(BaseModel):
    """A versioned collection of policy rules for one regulation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int
    id: str = Field(min_length=1)
    regulation: str = Field(min_length=1, description="e.g. 'EU AI Act'.")
    version: str = Field(min_length=1)
    rules: list[PolicyRule] = Field(min_length=1)

    @field_validator("rules")
    @classmethod
    def _ids_unique(cls, rules: list[PolicyRule]) -> list[PolicyRule]:
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise ValueError(f"duplicate policy rule id: {rule.id!r}")
            seen.add(rule.id)
        return rules
