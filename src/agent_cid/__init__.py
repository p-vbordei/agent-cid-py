"""agent-cid — content-addressed artifact manifest for AI agents."""

from .build import build
from .cid import bytes_to_cid, verify_cid
from .did import (
    did_key_to_pubkey,
    did_web_to_url,
    parse_ed25519_from_did_doc,
    pubkey_to_did_key,
)
from .did_web import fetch_did_web_pubkey
from .types import (
    BuildOpts,
    DidResolver,
    Manifest,
    Signature,
    SignerInput,
    VerifyOptions,
    VerifyResult,
)
from .verify import verify, verify_chain

__all__ = [
    "BuildOpts",
    "DidResolver",
    "Manifest",
    "Signature",
    "SignerInput",
    "VerifyOptions",
    "VerifyResult",
    "build",
    "bytes_to_cid",
    "did_key_to_pubkey",
    "did_web_to_url",
    "fetch_did_web_pubkey",
    "parse_ed25519_from_did_doc",
    "pubkey_to_did_key",
    "verify",
    "verify_cid",
    "verify_chain",
]
