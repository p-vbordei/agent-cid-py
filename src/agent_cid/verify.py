"""verify() + verify_chain() for agent-cid manifests."""

from __future__ import annotations

import inspect
import time
from typing import Any

from .canonical import canonical_encode
from .cid import verify_cid
from .did import did_key_to_pubkey
from .did_web import fetch_did_web_pubkey
from .sign import b64decode, verify_bytes
from .types import DidResolver, VerifyOptions, VerifyResult

_RESOLVER_CACHE_TTL_MS = 5 * 60 * 1000

# Per-resolver cache; keyed by resolver function identity.
_resolver_caches: dict[int, dict[str, tuple[bytes, float]]] = {}


def __reset_resolver_cache() -> None:
    """Test-only: clear resolver caches."""
    _resolver_caches.clear()


async def _builtin_resolver(did: str) -> bytes:
    if did.startswith("did:key:"):
        return did_key_to_pubkey(did)
    if did.startswith("did:web:"):
        return await fetch_did_web_pubkey(did)
    raise ValueError(f"unsupported DID method: {did}")


def _with_cache(inner: DidResolver, ttl_ms: int = _RESOLVER_CACHE_TTL_MS) -> DidResolver:
    async def wrapped(did: str) -> bytes:
        key = id(inner)
        cache = _resolver_caches.setdefault(key, {})
        now = time.time() * 1000
        hit = cache.get(did)
        if hit and hit[1] > now:
            return hit[0]
        result = inner(did)
        if inspect.isawaitable(result):
            result = await result
        cache[did] = (result, now + ttl_ms)
        return result

    return wrapped


def _validate_manifest(m: Any) -> tuple[bool, list[str]]:
    """Lightweight schema validation matching zod constraints."""
    errors: list[str] = []
    if not isinstance(m, dict):
        return False, ["schema: root not an object"]
    if m.get("v") != "agent-cid/1":
        errors.append('schema: v must be "agent-cid/1"')
    for key in ("cid", "media_type", "schema_uri", "producer", "created_at"):
        v = m.get(key)
        if not isinstance(v, str) or not v:
            errors.append(f"schema: {key} must be non-empty string")
    if not isinstance(m.get("size"), int) or m["size"] < 0:
        errors.append("schema: size must be non-negative integer")
    producer = m.get("producer", "")
    if isinstance(producer, str) and not producer.startswith("did:"):
        errors.append("schema: producer must start with did:")
    if "parent_cid" in m and (not isinstance(m["parent_cid"], str) or not m["parent_cid"]):
        errors.append("schema: parent_cid must be non-empty string")
    retention = m.get("retention")
    if retention is not None and not isinstance(retention, dict):
        errors.append("schema: retention must be object")
    sigs = m.get("sigs")
    if not isinstance(sigs, list) or not sigs:
        errors.append("schema: sigs must be non-empty array")
    else:
        for i, s in enumerate(sigs):
            if not isinstance(s, dict):
                errors.append(f"schema: sigs[{i}] not object")
                continue
            sd = s.get("signer_did", "")
            if not isinstance(sd, str) or not sd.startswith("did:"):
                errors.append(f"schema: sigs[{i}].signer_did must start with did:")
            if s.get("alg") != "ed25519":
                errors.append(f'schema: sigs[{i}].alg must be "ed25519"')
            if not isinstance(s.get("sig"), str) or not s["sig"]:
                errors.append(f"schema: sigs[{i}].sig must be non-empty string")
    return (len(errors) == 0), errors


async def verify(
    manifest: Any,
    data: bytes,
    options: VerifyOptions | None = None,
) -> VerifyResult:
    options = options or VerifyOptions()
    base_resolver: DidResolver = options.resolver or _builtin_resolver
    resolver = base_resolver if options.resolver_cache is False else _with_cache(base_resolver)
    now_ms = options.now if options.now is not None else time.time() * 1000
    errors: list[str] = []
    warnings: list[str] = []

    ok, schema_errs = _validate_manifest(manifest)
    if not ok:
        return VerifyResult(ok=False, errors=schema_errs, warnings=warnings)

    m: dict = manifest

    if m["size"] != len(data):
        errors.append(f"size mismatch: manifest {m['size']}, body {len(data)}")
    if not verify_cid(m["cid"], data):
        errors.append("cid mismatch")

    retention = m.get("retention") or {}
    expires_at = retention.get("expires_at")
    if expires_at:
        exp_ms = _parse_iso_ms(expires_at)
        if exp_ms is not None and now_ms > exp_ms:
            if options.ignore_expiry:
                warnings.append(f"expired at {expires_at} (ignored)")
            else:
                errors.append(f"expired at {expires_at}")
    stale_after = retention.get("stale_after")
    if stale_after:
        stale_ms = _parse_iso_ms(stale_after)
        if stale_ms is not None and now_ms > stale_ms:
            warnings.append(f"stale since {stale_after}")

    sigs = m["sigs"]
    unsigned = {k: v for k, v in m.items() if k != "sigs"}
    canonical = canonical_encode(unsigned)
    for i, s in enumerate(sigs):
        try:
            result = resolver(s["signer_did"])
            if inspect.isawaitable(result):
                pub = await result
            else:
                pub = result
            if not verify_bytes(b64decode(s["sig"]), canonical, pub):
                errors.append(f"sigs[{i}]: invalid signature for {s['signer_did']}")
        except Exception as e:  # noqa: BLE001
            errors.append(f"sigs[{i}]: {e}")

    return VerifyResult(ok=(len(errors) == 0), errors=errors, warnings=warnings)


async def verify_chain(
    chain: list[dict],
    options: VerifyOptions | None = None,
) -> VerifyResult:
    """chain = [{"manifest": ..., "bytes": ...}, ...]"""
    errors: list[str] = []
    warnings: list[str] = []
    prev_cid: str | None = None

    for i, link in enumerate(chain):
        r = await verify(link["manifest"], link["bytes"], options)
        for w in r.warnings:
            warnings.append(f"chain[{i}]: {w}")
        if not r.ok:
            for e in r.errors:
                errors.append(f"chain[{i}]: {e}")
        m = link["manifest"]
        if isinstance(m, dict):
            if i > 0:
                if m.get("parent_cid") != prev_cid:
                    errors.append(
                        f"chain[{i}]: parent_cid mismatch — expected {prev_cid}, "
                        f"got {m.get('parent_cid', '<missing>')}"
                    )
            prev_cid = m.get("cid")

    return VerifyResult(ok=(len(errors) == 0), errors=errors, warnings=warnings)


def _parse_iso_ms(s: str) -> float | None:
    from datetime import datetime

    try:
        norm = s.replace("Z", "+00:00") if s.endswith("Z") else s
        return datetime.fromisoformat(norm).timestamp() * 1000
    except (ValueError, TypeError):
        return None
