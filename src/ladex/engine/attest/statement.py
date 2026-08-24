"""in-toto Statements and DSSE envelopes.

Ladex records human declarations as **in-toto Statements** (subject = the component, a typed
predicate = the claim) wrapped in a **DSSE envelope** — the same envelope format Sigstore and
in-toto use, so swapping the local signer for Sigstore keyless later changes only who signs,
not the artifact shape. The signature is computed over the DSSE **PAE** (Pre-Authentication
Encoding) of ``(payloadType, payload)``, per the DSSE spec.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://ladex.dev/attestation/v1"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: what actually gets signed."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(t), t, len(payload), payload)


def build_statement(subject: str, claim: str, value: str, attester: str, created: str) -> bytes:
    """Serialize an in-toto Statement to canonical (sorted, compact) JSON bytes."""
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    statement: dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject, "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "claim": claim,
            "value": value,
            "attester": attester,
            "created": created,
        },
    }
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_envelope(payload: bytes, *, keyid: str, signature_b64: str) -> dict[str, Any]:
    """Assemble a DSSE envelope around a signed payload."""
    import base64

    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": signature_b64}],
    }


def envelope_statement(envelope: dict[str, Any]) -> dict[str, Any]:
    """Decode the in-toto Statement carried by a DSSE envelope."""
    import base64

    payload = base64.b64decode(envelope["payload"])
    result: dict[str, Any] = json.loads(payload)
    return result
