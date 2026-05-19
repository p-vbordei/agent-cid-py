"""DID key/web helpers."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

import base58

_ED25519_MULTICODEC = 0xED
_ED25519_PREFIX = bytes([0xED, 0x01])


def pubkey_to_did_key(pubkey: bytes) -> str:
    if len(pubkey) != 32:
        raise ValueError(f"ed25519 pubkey must be 32 bytes, got {len(pubkey)}")
    encoded = base58.b58encode(_ED25519_PREFIX + pubkey).decode("ascii")
    return f"did:key:z{encoded}"


def did_key_to_pubkey(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError(f'not a did:key (must start with "did:key:z"): {did}')
    decoded = base58.b58decode(did[len("did:key:z") :])
    code, code_len = _varint_decode(decoded)
    if code != _ED25519_MULTICODEC:
        raise ValueError(f"unsupported did:key multicodec 0x{code:x} (want ed25519 0xed)")
    pub = decoded[code_len:]
    if len(pub) != 32:
        raise ValueError(f"did:key pubkey has wrong length {len(pub)} (want 32)")
    return bytes(pub)


def _varint_decode(data: bytes) -> tuple[int, int]:
    n = 0
    shift = 0
    i = 0
    for byte in data:
        n |= (byte & 0x7F) << shift
        i += 1
        if not (byte & 0x80):
            return n, i
        shift += 7
    raise ValueError("varint overflow")


def did_web_to_url(did: str) -> str:
    if not did.startswith("did:web:"):
        raise ValueError(f"not a did:web: {did}")
    tail = did[len("did:web:") :]
    parts = [unquote(p) for p in tail.split(":")]
    host = parts[0] if parts else ""
    rest = parts[1:]
    if not host:
        raise ValueError("did:web missing host")
    if any(p in ("", ".", "..") for p in rest):
        raise ValueError(f"did:web path segment rejected: {'/'.join(rest)}")
    if not rest:
        return f"https://{host}/.well-known/did.json"
    return f"https://{host}/{'/'.join(rest)}/did.json"


def parse_ed25519_from_did_doc(doc: Any, signer_did: str) -> bytes:
    methods = doc.get("verificationMethod") if isinstance(doc, dict) else None
    if not isinstance(methods, list):
        raise ValueError("DID document has no verificationMethod")
    for m in methods:
        if not isinstance(m, dict):
            continue
        ctrl = m.get("controller")
        mid = m.get("id", "")
        if ctrl != signer_did and not mid.startswith(f"{signer_did}#"):
            continue
        if m.get("type") != "Ed25519VerificationKey2020":
            continue
        mb = m.get("publicKeyMultibase")
        if not mb:
            continue
        # publicKeyMultibase uses the same z-prefixed base58btc + 0xed01 multicodec as did:key.
        return did_key_to_pubkey(f"did:key:{mb}")
    raise ValueError(f"no Ed25519 verification method found for {signer_did}")
