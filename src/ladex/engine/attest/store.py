"""Persistent, committable store of signed attestations.

Attestations live in ``<repo>/.ladex/attestations.json`` — committed to the repo, so the
signed human declarations travel with the code (provenance captured at creation time). The
BOM is *regenerated* on every scan, so it can't be the source of truth; it embeds verified
attestations pulled from this store.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STORE_DIRNAME = ".ladex"
STORE_FILENAME = "attestations.json"
STORE_VERSION = 1


@dataclass(frozen=True, slots=True)
class Attestation:
    """One signed human declaration about a component."""

    subject: str
    claim: str
    value: str
    attester: str
    created: str
    keyid: str
    public_key_b64: str
    envelope: dict[str, Any]
    bindings: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "claim": self.claim,
            "value": self.value,
            "attester": self.attester,
            "created": self.created,
            "keyid": self.keyid,
            "public_key": self.public_key_b64,
            "bindings": self.bindings,
            "envelope": self.envelope,
        }

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> Attestation:
        return Attestation(
            subject=raw["subject"],
            claim=raw["claim"],
            value=raw["value"],
            attester=raw["attester"],
            created=raw["created"],
            keyid=raw["keyid"],
            public_key_b64=raw["public_key"],
            envelope=raw["envelope"],
            bindings=raw.get("bindings", {}),
        )


def store_path(root: Path) -> Path:
    return root / STORE_DIRNAME / STORE_FILENAME


class AttestationStore:
    """Read/write access to a project's attestation file."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @classmethod
    def for_root(cls, root: Path) -> AttestationStore:
        return cls(store_path(root))

    def load(self) -> list[Attestation]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [Attestation.from_dict(a) for a in raw.get("attestations", [])]

    def add(self, attestation: Attestation) -> None:
        """Append an attestation, replacing any prior one for the same (subject, claim)."""
        existing = [
            a
            for a in self.load()
            if not (a.subject == attestation.subject and a.claim == attestation.claim)
        ]
        existing.append(attestation)
        self._save(existing)

    def _save(self, attestations: list[Attestation]) -> None:
        ordered = sorted(attestations, key=lambda a: (a.subject, a.claim))
        payload = {
            "version": STORE_VERSION,
            "attestations": [a.to_dict() for a in ordered],
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
