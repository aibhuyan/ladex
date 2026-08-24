"""Attestation: sign, verify, tamper-detect, persist, and the local key lifecycle."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from ladex.engine.attest import (
    AttestationStore,
    LocalSigner,
    create_attestation,
    get_signer,
    verify_attestation,
)
from ladex.engine.attest.signer import verify_signature
from ladex.engine.attest.statement import envelope_statement, pae


@pytest.fixture
def signer(tmp_path: Path) -> LocalSigner:
    return LocalSigner(key_path=tmp_path / "key.ed25519")


def test_local_key_is_created_and_reused(tmp_path: Path) -> None:
    key_path = tmp_path / "key.ed25519"
    assert not key_path.exists()
    s1 = LocalSigner(key_path=key_path)
    assert key_path.exists()
    r1 = s1.sign(b"hello")
    # A second signer loading the same key yields the same keyid/public key.
    s2 = LocalSigner(key_path=key_path)
    r2 = s2.sign(b"hello")
    assert r1.keyid == r2.keyid
    assert r1.public_key_b64 == r2.public_key_b64


def test_sign_and_verify_roundtrip(signer: LocalSigner) -> None:
    att = create_attestation(
        "org/model", "provenance", "public data, apache-2.0", "dev@example.com", signer
    )
    assert verify_attestation(att) is True
    assert att.subject == "org/model"
    assert att.claim == "provenance"


def test_envelope_carries_the_signed_statement(signer: LocalSigner) -> None:
    att = create_attestation("m", "consent_basis", "GDPR 6(1)(a)", "dev@x", signer)
    statement = envelope_statement(att.envelope)
    assert statement["subject"][0]["name"] == "m"
    assert statement["predicate"]["value"] == "GDPR 6(1)(a)"


def test_tampering_with_value_fails_verification(signer: LocalSigner) -> None:
    att = create_attestation("m", "provenance", "honest value", "dev@x", signer)
    tampered = dataclasses.replace(att, value="forged value")
    # The signature still covers the original statement, so the mismatch is caught.
    assert verify_attestation(tampered) is False


def test_tampering_with_signature_fails(signer: LocalSigner) -> None:
    att = create_attestation("m", "provenance", "v", "dev@x", signer)
    bad_env = {**att.envelope}
    bad_env["signatures"] = [{"keyid": att.keyid, "sig": "AAAA"}]
    tampered = dataclasses.replace(att, envelope=bad_env)
    assert verify_attestation(tampered) is False


def test_wrong_key_does_not_verify(tmp_path: Path) -> None:
    payload = pae("application/vnd.in-toto+json", b"{}")
    a = LocalSigner(key_path=tmp_path / "a").sign(payload)
    b = LocalSigner(key_path=tmp_path / "b").sign(payload)
    # b's public key must not verify a's signature.
    assert verify_signature(payload, a.signature_b64, b.public_key_b64) is False
    assert verify_signature(payload, a.signature_b64, a.public_key_b64) is True


def test_store_roundtrip_and_replace(tmp_path: Path, signer: LocalSigner) -> None:
    store = AttestationStore.for_root(tmp_path)
    store.add(create_attestation("m", "provenance", "v1", "dev@x", signer))
    assert len(store.load()) == 1
    # Re-attesting the same (subject, claim) replaces rather than duplicates.
    store.add(create_attestation("m", "provenance", "v2", "dev@x", signer))
    loaded = store.load()
    assert len(loaded) == 1
    assert loaded[0].value == "v2"


def test_store_is_stable_on_disk(tmp_path: Path, signer: LocalSigner) -> None:
    store = AttestationStore.for_root(tmp_path)
    att = create_attestation(
        "m", "provenance", "v", "dev@x", signer, created="2026-01-01T00:00:00+00:00"
    )
    store.add(att)
    first = (tmp_path / ".ladex" / "attestations.json").read_text(encoding="utf-8")
    store.add(att)
    second = (tmp_path / ".ladex" / "attestations.json").read_text(encoding="utf-8")
    assert first == second


def test_sigstore_backend_is_opt_in_stub() -> None:
    with pytest.raises(NotImplementedError, match="Sigstore"):
        get_signer("sigstore")
