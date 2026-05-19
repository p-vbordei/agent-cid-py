"""CIDv1 (raw codec, sha256 multihash, base32 lowercase) encoding."""

from __future__ import annotations

import base64
import hashlib

# Multicodec codes (unsigned varint).
_CID_VERSION = 0x01
_CODEC_RAW = 0x55
_MULTIHASH_SHA256 = 0x12
_DIGEST_LEN = 0x20


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def bytes_to_cid(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    cid_bytes = (
        _varint(_CID_VERSION)
        + _varint(_CODEC_RAW)
        + _varint(_MULTIHASH_SHA256)
        + _varint(_DIGEST_LEN)
        + digest
    )
    # base32 lowercase, no padding (multibase 'b').
    b32 = base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")
    return "b" + b32


def verify_cid(cid: str, data: bytes) -> bool:
    return bytes_to_cid(data) == cid
