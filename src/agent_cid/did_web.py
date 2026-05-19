"""did:web public key fetch over HTTPS."""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import httpx

from .did import did_web_to_url, parse_ed25519_from_did_doc

_DEFAULT_TIMEOUT_MS = 5000
_DEFAULT_SIZE_LIMIT = 64 * 1024

FetchLike = Callable[[str], Awaitable[bytes]]


async def fetch_did_web_pubkey(
    did: str,
    *,
    fetch: FetchLike | None = None,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    size_limit: int = _DEFAULT_SIZE_LIMIT,
) -> bytes:
    url = did_web_to_url(did)
    if not url.startswith("https://"):
        raise ValueError(f"did:web requires https://, got {url}")

    if fetch is not None:
        body = await fetch(url)
    else:
        async with httpx.AsyncClient(timeout=timeout_ms / 1000) as client:
            resp = await client.get(url, headers={"accept": "application/json"})
        if resp.status_code >= 400:
            raise RuntimeError(f"did:web fetch {did}: HTTP {resp.status_code}")
        body = resp.content

    if len(body) > size_limit:
        raise RuntimeError(f"did:web doc size {len(body)} > limit {size_limit}")
    import json

    doc = json.loads(body.decode("utf-8"))
    return parse_ed25519_from_did_doc(doc, did)
