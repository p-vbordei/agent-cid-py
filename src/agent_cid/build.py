"""build(): compute CID, fill manifest, attach signatures."""

from __future__ import annotations

import inspect
from datetime import datetime, timezone

from .canonical import canonical_encode
from .cid import bytes_to_cid
from .sign import b64encode
from .types import BuildOpts, Manifest, Signature


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


async def build(data: bytes, opts: BuildOpts) -> Manifest:
    if not opts.signers:
        raise ValueError("build requires at least one signer")
    cid = bytes_to_cid(data)
    unsigned: dict = {
        "v": "agent-cid/1",
        "cid": cid,
        "size": len(data),
        "media_type": opts.media_type,
        "schema_uri": opts.schema_uri,
        "producer": opts.producer_did,
        "created_at": opts.created_at or _iso(datetime.now(timezone.utc)),
    }
    if opts.parent_cid is not None:
        unsigned["parent_cid"] = opts.parent_cid
    if opts.retention is not None:
        unsigned["retention"] = opts.retention

    canonical = canonical_encode(unsigned)
    sigs: list[Signature] = []
    for s in opts.signers:
        result = s.sign_fn(canonical)
        if inspect.isawaitable(result):
            result = await result
        sigs.append({"signer_did": s.did, "alg": "ed25519", "sig": b64encode(result)})
    return {**unsigned, "sigs": sigs}
