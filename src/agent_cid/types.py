"""Public types for agent-cid (Python port)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypedDict


class Signature(TypedDict):
    signer_did: str
    alg: str  # "ed25519"
    sig: str  # base64


class Retention(TypedDict, total=False):
    stale_after: str
    expires_at: str


class Manifest(TypedDict, total=False):
    v: str  # "agent-cid/1"
    cid: str
    size: int
    media_type: str
    schema_uri: str
    producer: str
    created_at: str
    parent_cid: str
    retention: Retention
    sigs: list[Signature]


SignFn = Callable[[bytes], Awaitable[bytes] | bytes]


@dataclass
class SignerInput:
    did: str
    sign_fn: SignFn


@dataclass
class BuildOpts:
    producer_did: str
    schema_uri: str
    media_type: str
    signers: list[SignerInput]
    parent_cid: str | None = None
    retention: Retention | None = None
    created_at: str | None = None


DidResolver = Callable[[str], Awaitable[bytes] | bytes]


@dataclass
class VerifyOptions:
    resolver: DidResolver | None = None
    resolver_cache: bool = True
    resolver_timeout_ms: int = 5000
    ignore_expiry: bool = False
    now: float | None = None  # epoch ms


@dataclass
class VerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
