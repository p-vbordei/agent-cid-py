"""Run the canonical TS conformance vectors against the Python port."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_cid import (
    BuildOpts,
    SignerInput,
    build,
    parse_ed25519_from_did_doc,
    pubkey_to_did_key,
    verify,
    verify_chain,
)
from agent_cid.canonical import canonical_encode
from agent_cid.types import VerifyOptions

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


def _load_priv(hex_str: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def _pub_bytes(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


async def _run_build(input_: dict) -> tuple[dict, bytes]:
    body = bytes.fromhex(input_["body_hex"])
    priv = _load_priv(input_["producer_priv_hex"])
    producer_did = pubkey_to_did_key(_pub_bytes(priv))
    signers = [SignerInput(did=producer_did, sign_fn=lambda b, sk=priv: sk.sign(b))]
    for s in input_.get("extra_signers", []) or []:
        sp = _load_priv(s["priv_hex"])
        sd = pubkey_to_did_key(_pub_bytes(sp))
        signers.append(SignerInput(did=sd, sign_fn=lambda b, sk=sp: sk.sign(b)))
    manifest = await build(
        body,
        BuildOpts(
            producer_did=producer_did,
            schema_uri=input_["schema_uri"],
            media_type=input_["media_type"],
            signers=signers,
            parent_cid=input_.get("parent_cid"),
            retention=input_.get("retention"),
            created_at=input_["created_at"],
        ),
    )
    return manifest, body


def _vector_ids():
    return [p.stem for p in sorted(VECTORS.glob("*.json"))]


@pytest.mark.parametrize(
    "vector_path",
    sorted(VECTORS.glob("*.json")),
    ids=_vector_ids(),
)
async def test_vector(vector_path: Path):
    v = json.loads(vector_path.read_text(encoding="utf-8"))
    kind = v["kind"]

    if kind == "roundtrip":
        manifest, body = await _run_build(v["build"])
        assert manifest["cid"] == v["expected"]["cid"], (
            f"cid mismatch: got {manifest['cid']}, want {v['expected']['cid']}"
        )
        r = await verify(manifest, body)
        assert r.ok == v["expected"]["verify_ok"], r.errors
    elif kind == "tampered_body":
        manifest, body = await _run_build(v["build"])
        offset = v["tamper_offset"]
        tampered = bytearray(body)
        tampered[offset] ^= 0xFF
        r = await verify(manifest, bytes(tampered))
        assert not r.ok
        wanted = v["expected"]["error_contains"]
        assert any(wanted in e for e in r.errors), r.errors
    elif kind == "parent_chain":
        built = []
        prev: str | None = None
        for link in v["links"]:
            link_in = dict(link)
            if link_in.get("parent_cid") is None:
                link_in["parent_cid"] = prev
            m, body = await _run_build(link_in)
            built.append({"manifest": m, "bytes": body})
            prev = m["cid"]
        idx = v.get("tamper_link_sig_index")
        if idx is not None:
            link = built[idx]
            m = dict(link["manifest"])
            old_sig = m["sigs"][0]
            m["sigs"] = [{**old_sig, "sig": "AAAA"}]
            built[idx] = {"manifest": m, "bytes": link["bytes"]}
        r = await verify_chain(built)
        assert not r.ok
        wanted = v["expected"]["error_contains"]
        assert any(wanted in e for e in r.errors), r.errors
    elif kind == "canonical":
        out = canonical_encode(v["input"]).decode("utf-8")
        assert out == v["expected_canonical"]
    elif kind == "did_web_roundtrip":
        body = bytes.fromhex(v["build"]["body_hex"])
        priv = _load_priv(v["build"]["producer_priv_hex"])
        manifest = await build(
            body,
            BuildOpts(
                producer_did=v["producer_did"],
                schema_uri=v["build"]["schema_uri"],
                media_type=v["build"]["media_type"],
                signers=[SignerInput(did=v["producer_did"], sign_fn=lambda b, sk=priv: sk.sign(b))],
                created_at=v["build"]["created_at"],
            ),
        )
        did_doc = v["did_doc"]
        opts = VerifyOptions(
            resolver=lambda did, doc=did_doc: parse_ed25519_from_did_doc(doc, did),
            resolver_cache=False,
        )
        r = await verify(manifest, body, opts)
        assert r.ok == v["expected"]["verify_ok"], r.errors
    else:
        pytest.fail(f"unknown vector kind: {kind}")
