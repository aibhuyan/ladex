"""Attestation: sign human answers for undocumented provenance and embed them in the BOM."""

from __future__ import annotations

from ladex.engine.attest.service import (
    ALL_CLAIMS,
    ATTESTABLE_CLAIMS,
    OBLIGATION_CLAIM,
    create_attestation,
    verify_attestation,
)
from ladex.engine.attest.signer import (
    LocalSigner,
    SignatureResult,
    Signer,
    get_signer,
    verify_signature,
)
from ladex.engine.attest.store import Attestation, AttestationStore, store_path

__all__ = [
    "ALL_CLAIMS",
    "ATTESTABLE_CLAIMS",
    "OBLIGATION_CLAIM",
    "Attestation",
    "AttestationStore",
    "LocalSigner",
    "SignatureResult",
    "Signer",
    "create_attestation",
    "get_signer",
    "store_path",
    "verify_attestation",
    "verify_signature",
]
