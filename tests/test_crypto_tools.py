"""Integration tests for /api/v1/commons/crypto/* — run against a live
surface-api at 127.0.0.1:3000 with a service-key + a seeded agent.

Mirrors the env contract used by every other commons test:

    SURFACE_BASE_URL          (default: http://127.0.0.1:3000)
    SURFACE_SERVICE_KEY       (or SERVICE_API_KEY)
    SURFACE_TEST_AGENT_ID

Covers:
  * health probe (public, no auth)
  * jwt-encode → jwt-decode round-trip across HS256/HS384/HS512
  * jwt-decode without a secret returns header+payload+verified=None
  * jwt-decode with the right secret returns verified=True; wrong secret
    returns verified=False
  * malformed JWT → 400
  * hash for md5/sha1/sha256/sha512 (hex + base64) matches stdlib
  * bcrypt round-trip verifies via `bcrypt.checkpw`
  * hmac across all supported algorithms matches stdlib
  * password-gen length / classes / entropy / count
  * uuid v1, v4, v5 (deterministic with namespace+name)
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import os
import uuid as _uuid

import bcrypt
import httpx
import jwt as _jwt
import pytest


BASE = os.environ.get("SURFACE_BASE_URL", "http://127.0.0.1:3000")
SVC_KEY = os.environ.get("SURFACE_SERVICE_KEY") or os.environ.get("SERVICE_API_KEY")
AGENT_ID = os.environ.get("SURFACE_TEST_AGENT_ID")


def _client() -> httpx.Client:
    if not SVC_KEY or not AGENT_ID:
        pytest.skip("SURFACE_SERVICE_KEY + SURFACE_TEST_AGENT_ID required")
    return httpx.Client(
        base_url=BASE,
        headers={"X-Service-Key": SVC_KEY, "X-Agent-Id": AGENT_ID},
        timeout=60.0,
    )


# ── health ───────────────────────────────────────────────────────────────

def test_health_public():
    r = httpx.get(f"{BASE}/api/v1/commons/crypto/health", timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert j["service"] == "commons.crypto"
    for endpoint in ("jwt-decode", "jwt-encode", "hash", "hmac", "password-gen", "uuid"):
        assert endpoint in j["endpoints"]
    assert j["sc_cost"]["jwt_decode"] == 1.0
    assert j["sc_cost"]["password_gen"] == 0.0
    for algo in ("md5", "sha1", "sha256", "sha512", "bcrypt"):
        assert algo in j["hash_algorithms"]
    for algo in ("HS256", "HS384", "HS512"):
        assert algo in j["jwt_algorithms"]


# ── jwt-encode / jwt-decode round-trip ───────────────────────────────────

@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_jwt_round_trip(alg: str):
    secret = "supersecret-" + _uuid.uuid4().hex
    payload = {"sub": "agent-x", "exp": 9999999999, "scope": ["read", "write"]}
    with _client() as c:
        # encode
        r = c.post(
            "/api/v1/commons/crypto/jwt-encode",
            json={"payload": payload, "secret": secret, "algorithm": alg},
        )
        assert r.status_code == 200, r.text
        token = r.json()["token"]
        assert token.count(".") == 2

        # decode WITHOUT secret — verified=None
        r = c.post(
            "/api/v1/commons/crypto/jwt-decode",
            json={"token": token},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["header"]["alg"] == alg
        assert d["payload"]["sub"] == "agent-x"
        assert d["signature_present"] is True
        assert d["verified"] is None

        # decode WITH right secret — verified=True
        r = c.post(
            "/api/v1/commons/crypto/jwt-decode",
            json={"token": token, "secret": secret},
        )
        d = r.json()
        assert d["verified"] is True
        assert d["verify_error"] is None

        # decode WITH wrong secret — verified=False
        r = c.post(
            "/api/v1/commons/crypto/jwt-decode",
            json={"token": token, "secret": "not-the-secret"},
        )
        d = r.json()
        assert d["verified"] is False


def test_jwt_decode_external_token_matches_stdlib():
    """Encode with PyJWT directly, then decode through our endpoint and
    confirm header+payload come back byte-for-byte."""
    secret = "another-secret"
    payload = {"hello": "world", "n": 42}
    token = _jwt.encode(payload, secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode()

    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/jwt-decode",
            json={"token": token, "secret": secret},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["header"] == {"alg": "HS256", "typ": "JWT"}
        assert d["payload"] == payload
        assert d["verified"] is True


def test_jwt_decode_malformed_rejected():
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/jwt-decode",
            json={"token": "not-a-jwt"},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "malformed_jwt"


# ── hash ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("algo", ["md5", "sha1", "sha256", "sha512"])
def test_hash_matches_stdlib_hex(algo: str):
    text = "the quick brown fox jumps over the lazy dog"
    expected = hashlib.new(algo, text.encode()).hexdigest()
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/hash",
            json={"text": text, "algorithm": algo},
        )
        assert r.status_code == 200, r.text
        assert r.json()["hash"] == expected


def test_hash_base64_encoding():
    text = "hello world"
    expected = base64.b64encode(hashlib.sha256(text.encode()).digest()).decode("ascii")
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/hash",
            json={"text": text, "algorithm": "sha256", "encoding": "base64"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["hash"] == expected


def test_bcrypt_hash_verifies():
    text = "correct horse battery staple"
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/hash",
            json={"text": text, "algorithm": "bcrypt", "rounds": 4},
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["hash"].startswith("$2")
        assert j["rounds"] == 4
        assert bcrypt.checkpw(text.encode(), j["hash"].encode()) is True
        assert bcrypt.checkpw(b"wrong", j["hash"].encode()) is False


# ── hmac ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("algo", ["md5", "sha1", "sha256", "sha384", "sha512"])
def test_hmac_matches_stdlib(algo: str):
    text = "payload to authenticate"
    secret = "shared-secret"
    expected = _hmac.new(
        secret.encode(), text.encode(), getattr(hashlib, algo)
    ).hexdigest()
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/hmac",
            json={"text": text, "secret": secret, "algorithm": algo},
        )
        assert r.status_code == 200, r.text
        assert r.json()["hmac"] == expected


# ── password-gen ─────────────────────────────────────────────────────────

def test_password_gen_default_strong():
    r = httpx.post(
        f"{BASE}/api/v1/commons/crypto/password-gen",
        json={"length": 24, "count": 5},
        timeout=10,
    )
    assert r.status_code == 200, r.text
    j = r.json()
    assert len(j["passwords"]) == 5
    for p in j["passwords"]:
        assert len(p) == 24
    assert j["entropy_bits"] > 100  # 24 chars × log2(~80) ≈ 152 bits
    assert j["sc_charged"] == 0.0


def test_password_gen_no_classes_rejected():
    r = httpx.post(
        f"{BASE}/api/v1/commons/crypto/password-gen",
        json={
            "length": 16,
            "include_lower": False,
            "include_upper": False,
            "include_digits": False,
            "include_symbols": False,
        },
        timeout=10,
    )
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "no_character_class_selected"


def test_password_gen_only_digits():
    r = httpx.post(
        f"{BASE}/api/v1/commons/crypto/password-gen",
        json={
            "length": 12,
            "include_lower": False,
            "include_upper": False,
            "include_digits": True,
            "include_symbols": False,
        },
        timeout=10,
    )
    j = r.json()
    assert all(c.isdigit() for c in j["passwords"][0])


# ── uuid ─────────────────────────────────────────────────────────────────

def test_uuid_v4_unique():
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/uuid",
            json={"version": 4, "count": 5},
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert len(set(j["uuids"])) == 5
        for u in j["uuids"]:
            obj = _uuid.UUID(u)
            assert obj.version == 4


def test_uuid_v1():
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/uuid",
            json={"version": 1, "count": 1},
        )
        assert r.status_code == 200, r.text
        u = r.json()["uuids"][0]
        assert _uuid.UUID(u).version == 1


def test_uuid_v5_deterministic():
    with _client() as c:
        body = {"version": 5, "namespace": "dns", "name": "agentnation.in"}
        r1 = c.post("/api/v1/commons/crypto/uuid", json=body)
        r2 = c.post("/api/v1/commons/crypto/uuid", json=body)
        assert r1.status_code == 200 and r2.status_code == 200
        u1 = r1.json()["uuids"][0]
        u2 = r2.json()["uuids"][0]
        assert u1 == u2
        # Confirm against stdlib
        expected = str(_uuid.uuid5(_uuid.NAMESPACE_DNS, "agentnation.in"))
        assert u1 == expected


def test_uuid_v5_requires_namespace_and_name():
    with _client() as c:
        r = c.post(
            "/api/v1/commons/crypto/uuid",
            json={"version": 5},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "v5_requires_namespace_and_name"
