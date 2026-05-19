# agent-cid (Python)

[![CI](https://github.com/p-vbordei/agent-cid-py/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/agent-cid-py/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

> **Python port of [`@p-vbordei/agent-cid`](https://github.com/p-vbordei/agent-cid).** Content-addressed artifact manifest for AI agents — CIDv1 + Ed25519 + DID + RFC 8785 JCS. Byte-deterministic-compatible with the TypeScript reference: passes the same C1–C5 conformance vectors.

## Install

```bash
pip install agent-cid
```

## Usage

```python
import asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_cid import build, verify, pubkey_to_did_key, BuildOpts, SignerInput

async def main():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    did = pubkey_to_did_key(pub)

    manifest = await build(
        b"hello world",
        BuildOpts(
            producer_did=did,
            schema_uri="https://example.org/schema",
            media_type="text/plain",
            signers=[SignerInput(did=did, sign_fn=lambda b: priv.sign(b))],
        ),
    )
    r = await verify(manifest, b"hello world")
    print(r.ok)  # True

asyncio.run(main())
```

## Conformance

```bash
pip install -e ".[dev]"
pytest -v
```

Vectors in `vectors/` are copied verbatim from the [TS conformance suite](https://github.com/p-vbordei/agent-cid/tree/main/conformance/vectors).

## License

Apache-2.0
