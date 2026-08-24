"""Create and verify attestations."""

from __future__ import annotations

from datetime import UTC, datetime

from ladex.engine.attest.signer import Signer, verify_signature
from ladex.engine.attest.statement import (
    build_envelope,
    build_statement,
    envelope_statement,
    pae,
)
from ladex.engine.attest.store import Attestation

#: Claims a human can attest — the fields no scanner can derive (see EnrichedModel).
ATTESTABLE_CLAIMS: tuple[str, ...] = ("provenance", "consent_basis")


def create_attestation(
    subject: str,
    claim: str,
    value: str,
    attester: str,
    signer: Signer,
    *,
    created: str | None = None,
) -> Attestation:
    """Build, sign, and package a human declaration as a DSSE-enveloped attestation."""
    created = created or datetime.now(UTC).isoformat()
    payload = build_statement(subject, claim, value, attester, created)
    sig = signer.sign(pae("application/vnd.in-toto+json", payload))
    envelope = build_envelope(payload, keyid=sig.keyid, signature_b64=sig.signature_b64)
    return Attestation(
        subject=subject,
        claim=claim,
        value=value,
        attester=attester,
        created=created,
        keyid=sig.keyid,
        public_key_b64=sig.public_key_b64,
        envelope=envelope,
    )


def verify_attestation(att: Attestation) -> bool:
    """True iff the signature is valid AND the stored index matches the signed statement.

    The second half is a tamper check: editing the plaintext ``value`` in the store without
    re-signing must fail verification, so a green attestation always reflects signed content.
    """
    import base64

    payload = base64.b64decode(att.envelope["payload"])
    ptype = att.envelope["payloadType"]
    sig_b64 = att.envelope["signatures"][0]["sig"]
    if not verify_signature(pae(ptype, payload), sig_b64, att.public_key_b64):
        return False

    statement = envelope_statement(att.envelope)
    predicate = statement.get("predicate", {})
    subject = statement.get("subject", [{}])[0].get("name")
    matches = (
        subject == att.subject
        and predicate.get("claim") == att.claim
        and predicate.get("value") == att.value
        and predicate.get("attester") == att.attester
    )
    return bool(matches)
