"""Result types for policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ladex.engine.policy.models import Severity, Verification


class ObligationStatus(StrEnum):
    """Whether an obligation definitely applies or depends on an undeclared project fact."""

    APPLIES = "applies"
    POTENTIALLY_APPLIES = "potentially_applies"


@dataclass(frozen=True, slots=True)
class Obligation:
    """One triggered obligation, with the components that triggered it and any open gaps."""

    rule_id: str
    regulation: str
    title: str
    citation: str
    obligation: str
    verification: Verification
    severity: Severity
    status: ObligationStatus
    components: tuple[str, ...]
    #: Project facts that are unknown; declaring them resolves POTENTIALLY_APPLIES.
    unresolved: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def is_gap(self) -> bool:
        """A gap is an obligation only a human attestation can satisfy (Step 7)."""
        return self.verification is Verification.REQUIRES_ATTESTATION

    def sort_key(self) -> tuple[str, str]:
        return (self.regulation, self.rule_id)


@dataclass(frozen=True, slots=True)
class PolicyReport:
    """The obligations produced by evaluating all bundles against one project."""

    obligations: tuple[Obligation, ...] = field(default_factory=tuple)

    @property
    def gaps(self) -> tuple[Obligation, ...]:
        return tuple(o for o in self.obligations if o.is_gap)

    @property
    def applies(self) -> tuple[Obligation, ...]:
        return tuple(o for o in self.obligations if o.status is ObligationStatus.APPLIES)

    @property
    def potential(self) -> tuple[Obligation, ...]:
        return tuple(
            o for o in self.obligations if o.status is ObligationStatus.POTENTIALLY_APPLIES
        )
