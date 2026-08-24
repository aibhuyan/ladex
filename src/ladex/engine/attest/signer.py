"""Signing backends for attestations.

Providers depend on the :class:`Signer` protocol, not on a concrete backend — the same seam
used for enrichment's ``Fetcher``. The default :class:`LocalSigner` uses an Ed25519 key that
Ladex auto-generates and stores in the user's config dir, so there is nothing to manage and
no network involved. A Sigstore keyless backend is the documented opt-in upgrade
(``ladex[sigstore]``); :func:`get_signer` is where it would be wired.

A local signature proves "the holder of this key signed this". Sigstore additionally binds the
signature to a *public identity* recorded in a transparency log — the reason to graduate to it
once attestations must be trusted by third parties.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import platformdirs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True, slots=True)
class SignatureResult:
    """A detached signature plus the material needed to verify it offline."""

    keyid: str
    signature_b64: str
    public_key_b64: str
    backend: str


class Signer(Protocol):
    """Anything that can sign bytes and expose its verifying key."""

    def sign(self, payload: bytes) -> SignatureResult: ...


def default_key_path() -> Path:
    return Path(platformdirs.user_config_dir("ladex")) / "signing_key.ed25519"


def _keyid(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


class LocalSigner:
    """Ed25519 signer backed by a locally stored key (generated on first use)."""

    backend = "local-ed25519"

    def __init__(self, key_path: Path | None = None) -> None:
        self._key_path = key_path if key_path is not None else default_key_path()
        self._private = self._load_or_create()

    def _load_or_create(self) -> Ed25519PrivateKey:
        if self._key_path.exists():
            raw = self._key_path.read_bytes()
            return Ed25519PrivateKey.from_private_bytes(raw)
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes_raw()
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key_path.write_bytes(raw)
        # Best-effort: restrict permissions where the OS honours it.
        with contextlib.suppress(OSError):
            self._key_path.chmod(0o600)
        return key

    def sign(self, payload: bytes) -> SignatureResult:
        signature = self._private.sign(payload)
        public_raw = self._private.public_key().public_bytes_raw()
        return SignatureResult(
            keyid=_keyid(public_raw),
            signature_b64=base64.b64encode(signature).decode("ascii"),
            public_key_b64=base64.b64encode(public_raw).decode("ascii"),
            backend=self.backend,
        )


def verify_signature(payload: bytes, signature_b64: str, public_key_b64: str) -> bool:
    """Verify an Ed25519 signature over ``payload`` using an embedded public key."""
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        public.verify(base64.b64decode(signature_b64), payload)
    except (InvalidSignature, ValueError):
        return False
    return True


def get_signer(backend: str = "local", *, key_path: Path | None = None) -> Signer:
    """Return a signer for ``backend``. Only 'local' is functional in v1."""
    if backend == "local":
        return LocalSigner(key_path=key_path)
    if backend == "sigstore":
        raise NotImplementedError(
            "Sigstore keyless signing is the documented opt-in upgrade path and is not yet "
            "wired in v1. Install `ladex[sigstore]` and use the local backend for now."
        )
    raise ValueError(f"unknown signing backend: {backend!r}")
