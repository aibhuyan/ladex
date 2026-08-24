"""Attestation: sign human answers for undocumented provenance and embed them in the BOM."""

from __future__ import annotations

from ladex.engine.attest.service import (
    ATTESTABLE_CLAIMS,
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
    "ATTESTABLE_CLAIMS",
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
