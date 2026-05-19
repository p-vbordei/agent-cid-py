"""Unit tests for CID encoding, did:key roundtrip, JCS."""

from __future__ import annotations

from agent_cid.canonical import canonical_encode
from agent_cid.cid import bytes_to_cid, verify_cid
from agent_cid.did import did_key_to_pubkey, did_web_to_url, pubkey_to_did_key


def test_cid_known_vector():
    data = b"hello world"
    cid = bytes_to_cid(data)
    assert cid.startswith("bafkrei")
    assert verify_cid(cid, data)
    assert not verify_cid(cid, b"hello WORLD")


def test_did_key_roundtrip():
    pub = bytes(range(32))
    did = pubkey_to_did_key(pub)
    assert did.startswith("did:key:z")
    assert did_key_to_pubkey(did) == pub


def test_did_web_to_url_well_known():
    assert did_web_to_url("did:web:example.com") == "https://example.com/.well-known/did.json"


def test_did_web_to_url_path():
    assert (
        did_web_to_url("did:web:example.com:agents:alice")
        == "https://example.com/agents/alice/did.json"
    )


def test_jcs_key_sort():
    assert canonical_encode({"b": 1, "a": 2}).decode() == '{"a":2,"b":1}'
