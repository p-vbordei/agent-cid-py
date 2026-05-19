# agent-cid (Python)

[![CI](https://github.com/p-vbordei/agent-cid-py/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/agent-cid-py/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-cid)](https://pypi.org/project/agent-cid/)
[![Spec](https://img.shields.io/badge/spec-v1.0-blue)](./SPEC.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](./LICENSE)

> **Idiomatic Python port of [@p-vbordei/agent-cid](https://github.com/p-vbordei/agent-cid).** Content-addressed artifact manifest for AI agents — CIDv1 + Ed25519 + DID + RFC 8785 JCS. Byte-deterministic-compatible with the TS reference; passes the same C1–C5 conformance suite.

## What's in the box

- `build(bytes, opts)` — compute CIDv1, fill the manifest, sign with one or more Ed25519 keys.
- `verify(manifest, bytes)` — schema + size + CID + signature + retention.
- `verify_chain([{manifest, bytes}, ...])` — traverse `parent_cid` chain.
- `pubkey_to_did_key()` / `did_key_to_pubkey()` — round-trip Ed25519 to `did:key`.
- `fetch_did_web_pubkey(did)` — HTTPS resolution with 64 KiB size cap and 5 s timeout.

## Install

```bash
pip install agent-cid
```

## Quickstart

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

    body = b'{"answer": 42}'
    manifest = await build(body, BuildOpts(
        producer_did=did,
        schema_uri="https://example.org/answer/1",
        media_type="application/json",
        signers=[SignerInput(did=did, sign_fn=lambda b: priv.sign(b))],
    ))
    result = await verify(manifest, body)
    print(manifest["cid"], result.ok)

asyncio.run(main())
```

Run it:

```bash
python examples/quickstart.py
# built v1: bafkreih...
# verify v1: True
# verify tampered: False
# built v2 (parent_cid set): True
```

## How it relates

| Repo | Role |
| --- | --- |
| [`agent-cid`](https://github.com/p-vbordei/agent-cid) (TS) | Reference implementation + normative SPEC + conformance vectors. |
| [`agent-cid-py`](https://github.com/p-vbordei/agent-cid-py) (this) | Idiomatic Python port; same vectors. |
| [`agent-cid-rs`](https://github.com/p-vbordei/agent-cid-rs) | Idiomatic Rust port; same vectors. |

## Conformance

```bash
uv sync --extra dev
uv run pytest -v
```

Vectors in `vectors/` are copied verbatim from the [TS conformance suite](https://github.com/p-vbordei/agent-cid/tree/main/conformance/vectors). Every C1–C5 vector must pass byte-identical to the TS reference.

| Clause | Vector | Check |
| --- | --- | --- |
| C1 | `c1-roundtrip` | Build then verify a 1 KiB body. |
| C2 | `c2-tampered-body` | Flip a byte; verify fails with `cid mismatch`. |
| C3 | `c3-parent-chain` | 3-version chain; tampered middle signer is flagged. |
| C4 | `c4-canonical` | JCS bytes match the reference. |
| C5 | `c5-did-web` | did:web resolver returns embedded DID doc pubkey. |

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Development

```bash
git clone https://github.com/p-vbordei/agent-cid-py
cd agent-cid-py
uv sync --extra dev
uv run pytest -v
uv run ruff check src tests
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
