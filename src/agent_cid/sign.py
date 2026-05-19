"""Ed25519 verify + base64 helpers."""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_bytes(sig: bytes, message: bytes, pubkey: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(pubkey)
        pk.verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s)
