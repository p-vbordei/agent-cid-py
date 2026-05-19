"""End-to-end demo for agent-cid (Python).

Mirrors examples/demo.ts in the TS reference:
  1. build a manifest over a small payload, verify it
  2. flip one byte → verify fails
  3. roll v2 with parent_cid = v1 cid, verify
"""

from __future__ import annotations

import asyncio
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_cid import BuildOpts, SignerInput, build, pubkey_to_did_key, verify


async def main() -> None:
    # Deterministic key — matches the TS demo's 0x42-fill private key.
    priv = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    did = pubkey_to_did_key(pub)

    opts_common = dict(
        producer_did=did,
        schema_uri="https://example.org/answer/1",
        media_type="application/json",
        signers=[SignerInput(did=did, sign_fn=lambda b: priv.sign(b))],
    )

    body_v1 = json.dumps({"answer": 42}, separators=(",", ":")).encode()
    m1 = await build(body_v1, BuildOpts(**opts_common))
    print(f"built v1: {m1['cid']}")
    print(f"verify v1: {(await verify(m1, body_v1)).ok}")

    tampered = bytearray(body_v1)
    tampered[0] ^= 0xFF
    r_bad = await verify(m1, bytes(tampered))
    print(f"verify tampered: {r_bad.ok}")

    body_v2 = json.dumps({"answer": 43}, separators=(",", ":")).encode()
    m2 = await build(body_v2, BuildOpts(parent_cid=m1["cid"], **opts_common))
    r2 = await verify(m2, body_v2)
    print(f"built v2 (parent_cid set): {r2.ok}")


if __name__ == "__main__":
    asyncio.run(main())
