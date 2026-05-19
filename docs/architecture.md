# agent-cid (Python) — Architecture

## Goal

Port the `agent-cid` v1.0 spec ([SPEC.md](../SPEC.md)) to idiomatic Python while keeping every byte that goes on the wire — CIDv1 strings, JCS-canonical manifest bytes, Ed25519 signatures — byte-identical with the TypeScript reference. Pass the same C1–C5 conformance vectors.

## Module map

| `src/agent_cid/<file>` | TS counterpart | Role |
| --- | --- | --- |
| `build.py` | `src/build.ts` | Compute CID, fill manifest, collect Ed25519 signatures over JCS-canonical bytes. |
| `verify.py` | `src/verify.ts` | Schema check, size check, CID check, signature verification, retention enforcement; per-resolver pubkey cache; `verify_chain` for `parent_cid` traversal. |
| `canonical.py` | `src/canonical.ts` | RFC 8785 JCS encoding wrapper. |
| `cid.py` | `src/cid.ts` | CIDv1 with raw codec + multihash sha-256, base32-lower string form. |
| `did.py` | `src/did.ts` | `did:key` codec for Ed25519; `did:web → URL` derivation; DID-doc Ed25519 lookup. |
| `did_web.py` | `src/did-web.ts` | HTTPS-only fetch with 64 KiB cap and 5 s timeout; default resolver for `did:web`. |
| `sign.py` | `src/sign.ts` | Ed25519 sign + verify, base64 codec. |
| `types.py` | `src/types.ts` | Public types — `Manifest`, `BuildOpts`, `VerifyOptions`, `VerifyResult`, `SignerInput`, `DidResolver`. |

## Dependency choices

| Concern | Library | Rationale |
| --- | --- | --- |
| Ed25519 sign / verify | [`cryptography`](https://cryptography.io) | Stdlib-grade, audited, ubiquitous. Already a transitive dep in most Python stacks. |
| JCS (RFC 8785) | [`jcs`](https://pypi.org/project/jcs/) | Direct RFC 8785 implementation; matches TS `canonicalize` output byte-for-byte. |
| Base58 | [`base58`](https://pypi.org/project/base58/) | Tiny, single-purpose; used for `did:key` multibase. |
| HTTP client | [`httpx`](https://www.python-httpx.org/) | Modern async client with timeout + max-bytes support out of the box. |
| Multihash / multiformats CID | inline | The CID surface used here (CIDv1 + raw + sha-256, base32-lower) is a 30-line implementation. Pulling `py-multiformats-cid` would add a heavy dep and lock the multibase. |

## Byte-determinism invariants

These are the points where any divergence from the TS reference would break conformance, so they are tested directly:

- **CIDv1 string** — base32-lower, raw codec (`0x55`), multihash sha-256 of the body. Output of `bytes_to_cid` must equal the TS output for the same body.
- **Canonical manifest bytes** — JCS-canonical JSON of the manifest with `sigs` removed. This is what signatures cover. Sort order, escaping, and number formatting all follow RFC 8785 via the `jcs` library.
- **Signature bytes** — Ed25519 over the canonical bytes; base64-encoded for transport. No domain separation, no prefix.

## Testing strategy

- **Unit** (`tests/test_unit.py`) — CID known vector, did:key roundtrip, did:web URL derivation, JCS key sort.
- **Conformance** (`tests/test_conformance.py`) — runs every vector under `vectors/` (C1–C5 + extras), each mapped to a `kind` (`roundtrip`, `tampered_body`, `parent_chain`, `canonical`, `did_web_roundtrip`). Vectors are copied verbatim from the TS reference.
- **Planned cross-impl byte equality** — a CI job that runs the TS, Python, and Rust ports against shared vectors and diffs canonical-bytes + CID + signature output. Tracked as future work; the per-port suites already catch divergence in practice because vectors fix the expected CID.

Any wire-format change must be proposed in the TS reference first and the vectors regenerated there. The ports follow.
