"""Crypto Tools — Commons guild crypto utilities bundle.

Open-source replacement for jwt.io / hash-it-online / lastpass-password-gen
browser tools. All endpoints are pure-Python on stdlib + ``pyjwt`` + ``bcrypt``
— no model calls, no external services.

Endpoints (all under ``/api/v1/commons/crypto``):

- ``POST /jwt-decode``    — decode a JWT (no verify); returns header+payload+
                            signature-presence flag. 1 SC.
- ``POST /jwt-encode``    — sign a JWT with given header/payload/secret.
                            HS256/HS384/HS512 only (no asymmetric). 1 SC.
- ``POST /hash``          — md5/sha1/sha256/sha512/bcrypt hex digest
                            (bcrypt → ``$2b$`` string). 1 SC.
- ``POST /hmac``          — HMAC-<algo>-hex (sha256/sha384/sha512/sha1/md5).
                            1 SC.
- ``POST /password-gen``  — strong random password + Shannon entropy bits.
                            FREE.
- ``POST /uuid``          — generate UUID v1/v4/v5 (v5 takes namespace+name).
                            1 SC.
- ``GET  /health``        — public probe.

Auth: free endpoints (``/password-gen``, ``/health``) take no auth.
Paid endpoints require ``X-Service-Key`` + ``X-Agent-Id`` and charge SC.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import math
import os
import secrets
import string
import time
import uuid as _uuid
from typing import Annotated, Any, Literal

import bcrypt
import jwt as _jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.service_auth import require_service_key_and_agent
from app.models.agent import Agent
from app.services.ledger import (
    InsufficientFundsError,
    record_transaction,
)


router = APIRouter(prefix="/api/v1/commons/crypto", tags=["commons-crypto"])


# ── SC pricing ────────────────────────────────────────────────────────────
SC_COST = {
    "jwt_decode":  float(os.environ.get("CRYPTO_SC_JWT_DECODE",  "1")),
    "jwt_encode":  float(os.environ.get("CRYPTO_SC_JWT_ENCODE",  "1")),
    "hash":        float(os.environ.get("CRYPTO_SC_HASH",        "1")),
    "hmac":        float(os.environ.get("CRYPTO_SC_HMAC",        "1")),
    "password_gen": 0.0,
    "uuid":        float(os.environ.get("CRYPTO_SC_UUID",        "1")),
}

# input guards
MAX_TEXT_BYTES = int(os.environ.get("CRYPTO_MAX_INPUT_BYTES", str(64 * 1024)))  # 64 KB
MAX_TOKEN_CHARS = int(os.environ.get("CRYPTO_MAX_TOKEN_CHARS", "16384"))
MAX_SECRET_CHARS = int(os.environ.get("CRYPTO_MAX_SECRET_CHARS", "4096"))
MAX_PASSWORD_LEN = int(os.environ.get("CRYPTO_MAX_PASSWORD_LEN", "256"))
MIN_PASSWORD_LEN = int(os.environ.get("CRYPTO_MIN_PASSWORD_LEN", "4"))


HASH_ALGOS = {"md5", "sha1", "sha256", "sha512", "bcrypt"}
HMAC_ALGOS = {"md5", "sha1", "sha256", "sha384", "sha512"}
JWT_ALGOS = {"HS256", "HS384", "HS512"}
UUID_VERSIONS = {1, 4, 5}
NAMESPACES = {
    "dns": _uuid.NAMESPACE_DNS,
    "url": _uuid.NAMESPACE_URL,
    "oid": _uuid.NAMESPACE_OID,
    "x500": _uuid.NAMESPACE_X500,
}


# ── input guards ──────────────────────────────────────────────────────────

def _check_size(s: str, *, name: str = "text", limit: int = MAX_TEXT_BYTES) -> None:
    if len(s.encode("utf-8")) > limit:
        raise HTTPException(
            status_code=413,
            detail={
                "error": "input_too_large",
                "field": name,
                "limit_bytes": limit,
            },
        )


# ── ledger / logging ──────────────────────────────────────────────────────

async def _log_tool_call(
    db: AsyncSession,
    *,
    agent_id: str,
    tool_name: str,
    input_summary: dict,
    output_len: int,
    sc_cost: float,
    latency_ms: int,
    error: str | None = None,
) -> None:
    await db.execute(
        text(
            """
            INSERT INTO tool_calls
                (id, agent_id, tool_name, input_json, output_len,
                 sc_cost, latency_ms, error, created_at)
            VALUES
                (:id, :agent_id, :tool_name, CAST(:input_json AS JSONB),
                 :output_len, :sc_cost, :latency_ms, :error, NOW())
            """
        ),
        {
            "id": str(_uuid.uuid4()),
            "agent_id": agent_id,
            "tool_name": tool_name,
            "input_json": json.dumps(input_summary, default=str),
            "output_len": output_len,
            "sc_cost": sc_cost,
            "latency_ms": latency_ms,
            "error": error,
        },
    )


async def _charge(
    db: AsyncSession,
    agent: Agent,
    *,
    amount: float,
    tool: str,
    ref: str,
) -> float:
    if amount <= 0:
        return 0.0
    try:
        await record_transaction(
            db,
            agent_id=agent.id,
            delta=-amount,
            reason=f"commons.crypto.{tool}",
            ref_id=ref,
            note=f"Crypto Tools: {tool}",
        )
    except InsufficientFundsError as e:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "insufficient_sc",
                "balance": e.balance,
                "needed": amount,
                "tool": f"commons.crypto.{tool}",
            },
        )
    return amount


# ── /health (public) ──────────────────────────────────────────────────────

@router.get("/health")
async def health() -> dict:
    return {
        "service": "commons.crypto",
        "version": "1.0.0",
        "endpoints": [
            "jwt-decode", "jwt-encode", "hash", "hmac",
            "password-gen", "uuid",
        ],
        "sc_cost": SC_COST,
        "limits": {
            "max_input_bytes": MAX_TEXT_BYTES,
            "max_token_chars": MAX_TOKEN_CHARS,
            "max_secret_chars": MAX_SECRET_CHARS,
            "min_password_len": MIN_PASSWORD_LEN,
            "max_password_len": MAX_PASSWORD_LEN,
        },
        "hash_algorithms": sorted(HASH_ALGOS),
        "hmac_algorithms": sorted(HMAC_ALGOS),
        "jwt_algorithms": sorted(JWT_ALGOS),
        "uuid_versions": sorted(UUID_VERSIONS),
        "uuid_namespaces": sorted(NAMESPACES.keys()),
    }


# ── /jwt-decode ───────────────────────────────────────────────────────────

class _JWTDecodeBody(BaseModel):
    token: str = Field(..., max_length=MAX_TOKEN_CHARS)
    secret: str | None = Field(
        None,
        max_length=MAX_SECRET_CHARS,
        description="Optional. If provided, signature is verified.",
    )


def _b64url_decode(s: str) -> bytes:
    """Pad-and-decode URL-safe base64 segment from a JWT."""
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception as e:
        raise HTTPException(
            status_code=400, detail={"error": "invalid_b64url", "reason": str(e)}
        )


def _decode_jwt_unverified(token: str) -> dict:
    """Return header + payload + a signature_present flag without verifying."""
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=400,
            detail={"error": "malformed_jwt", "reason": "expected_3_parts"},
        )
    h_raw, p_raw, sig_raw = parts
    try:
        header = json.loads(_b64url_decode(h_raw))
        payload = json.loads(_b64url_decode(p_raw))
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_json_segment", "reason": str(e)},
        )
    if not isinstance(header, dict):
        raise HTTPException(
            status_code=400,
            detail={"error": "header_not_object"},
        )
    if not isinstance(payload, dict):
        # Some JWT-like tokens have non-dict payloads; we still surface them.
        payload = {"_value": payload}
    return {
        "header": header,
        "payload": payload,
        "signature_present": bool(sig_raw),
        "signature_b64": sig_raw,
    }


@router.post("/jwt-decode")
async def jwt_decode(
    body: _JWTDecodeBody,
    agent: Annotated[Agent, Depends(require_service_key_and_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    t0 = time.perf_counter()
    _check_size(body.token, name="token", limit=MAX_TOKEN_CHARS)
    err: str | None = None
    out: dict[str, Any] = {}
    try:
        out = _decode_jwt_unverified(body.token)
        verified: bool | None = None
        verify_error: str | None = None
        algorithm = out["header"].get("alg") if isinstance(out["header"], dict) else None
        if body.secret is not None and algorithm:
            try:
                _jwt.decode(
                    body.token,
                    body.secret,
                    algorithms=[algorithm] if algorithm in JWT_ALGOS else list(JWT_ALGOS),
                    options={"verify_aud": False, "verify_exp": False, "verify_nbf": False, "verify_iat": False},
                )
                verified = True
            except _jwt.InvalidSignatureError:
                verified = False
                verify_error = "invalid_signature"
            except _jwt.InvalidTokenError as e:
                verified = False
                verify_error = str(e)
        out["verified"] = verified
        out["verify_error"] = verify_error
    except HTTPException:
        err = "decode_failed"
        raise
    finally:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            ref = str(_uuid.uuid4())
            sc = await _charge(
                db, agent, amount=SC_COST["jwt_decode"], tool="jwt_decode", ref=ref
            )
            out["sc_charged"] = sc
            await _log_tool_call(
                db,
                agent_id=agent.id,
                tool_name="commons.crypto.jwt_decode",
                input_summary={"token_len": len(body.token), "secret_provided": body.secret is not None},
                output_len=len(json.dumps(out, default=str)),
                sc_cost=sc,
                latency_ms=latency_ms,
                error=err,
            )
            await db.commit()
        except HTTPException:
            await db.rollback()
            raise
        except Exception:
            await db.rollback()
    return out


# ── /jwt-encode ───────────────────────────────────────────────────────────

class _JWTEncodeBody(BaseModel):
    header: dict[str, Any] | None = Field(
        None,
        description="Optional extra header fields. `alg` and `typ` are set automatically.",
    )
    payload: dict[str, Any] = Field(..., description="JWT claims to encode.")
    secret: str = Field(..., min_length=1, max_length=MAX_SECRET_CHARS)
    algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"


@router.post("/jwt-encode")
async def jwt_encode(
    body: _JWTEncodeBody,
    agent: Annotated[Agent, Depends(require_service_key_and_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    t0 = time.perf_counter()
    payload_size = len(json.dumps(body.payload, default=str))
    if payload_size > MAX_TEXT_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "payload_too_large", "limit_bytes": MAX_TEXT_BYTES},
        )
    extra_header = body.header or {}
    if not isinstance(extra_header, dict):
        raise HTTPException(status_code=400, detail={"error": "header_not_object"})

    err: str | None = None
    token = ""
    try:
        token = _jwt.encode(
            body.payload,
            body.secret,
            algorithm=body.algorithm,
            headers=extra_header or None,
        )
        # PyJWT 1.x returned bytes, 2.x returns str; normalise.
        if isinstance(token, bytes):
            token = token.decode("utf-8")
    except Exception as e:
        err = "encode_failed"
        raise HTTPException(
            status_code=400,
            detail={"error": "jwt_encode_failed", "reason": str(e)},
        ) from e
    finally:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            ref = str(_uuid.uuid4())
            sc = await _charge(
                db, agent, amount=SC_COST["jwt_encode"], tool="jwt_encode", ref=ref
            )
            await _log_tool_call(
                db,
                agent_id=agent.id,
                tool_name="commons.crypto.jwt_encode",
                input_summary={
                    "alg": body.algorithm,
                    "payload_size": payload_size,
                    "header_keys": list(extra_header.keys()),
                },
                output_len=len(token),
                sc_cost=sc,
                latency_ms=latency_ms,
                error=err,
            )
            await db.commit()
        except HTTPException:
            await db.rollback()
            raise
        except Exception:
            await db.rollback()
    return {
        "token": token,
        "algorithm": body.algorithm,
        "sc_charged": SC_COST["jwt_encode"],
    }


# ── /hash ─────────────────────────────────────────────────────────────────

class _HashBody(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_BYTES)
    algorithm: Literal["md5", "sha1", "sha256", "sha512", "bcrypt"] = "sha256"
    encoding: Literal["hex", "base64"] = "hex"
    rounds: int | None = Field(
        None, ge=4, le=15,
        description="bcrypt cost (4-15). Default 12. Ignored for other algos.",
    )


def _digest(data: bytes, algo: str, encoding: str) -> str:
    h = hashlib.new(algo)
    h.update(data)
    if encoding == "base64":
        return base64.b64encode(h.digest()).decode("ascii")
    return h.hexdigest()


@router.post("/hash")
async def hash_text(
    body: _HashBody,
    agent: Annotated[Agent, Depends(require_service_key_and_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    t0 = time.perf_counter()
    _check_size(body.text)
    err: str | None = None
    out: dict[str, Any] = {"algorithm": body.algorithm}
    try:
        data = body.text.encode("utf-8")
        if body.algorithm == "bcrypt":
            rounds = body.rounds or 12
            digest_str = bcrypt.hashpw(data, bcrypt.gensalt(rounds)).decode("ascii")
            out.update({
                "hash": digest_str,
                "rounds": rounds,
                "encoding": "modular_crypt",
            })
        else:
            digest_str = _digest(data, body.algorithm, body.encoding)
            out.update({"hash": digest_str, "encoding": body.encoding})
    except HTTPException:
        err = "hash_failed"
        raise
    except Exception as e:
        err = "hash_failed"
        raise HTTPException(
            status_code=400, detail={"error": "hash_failed", "reason": str(e)}
        ) from e
    finally:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            ref = str(_uuid.uuid4())
            sc = await _charge(
                db, agent, amount=SC_COST["hash"], tool="hash", ref=ref
            )
            out["sc_charged"] = sc
            await _log_tool_call(
                db,
                agent_id=agent.id,
                tool_name="commons.crypto.hash",
                input_summary={
                    "alg": body.algorithm,
                    "input_bytes": len(body.text.encode("utf-8")),
                    "encoding": body.encoding,
                },
                output_len=len(out.get("hash", "") or ""),
                sc_cost=sc,
                latency_ms=latency_ms,
                error=err,
            )
            await db.commit()
        except HTTPException:
            await db.rollback()
            raise
        except Exception:
            await db.rollback()
    return out


# ── /hmac ─────────────────────────────────────────────────────────────────

class _HMACBody(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_BYTES)
    secret: str = Field(..., min_length=1, max_length=MAX_SECRET_CHARS)
    algorithm: Literal["md5", "sha1", "sha256", "sha384", "sha512"] = "sha256"
    encoding: Literal["hex", "base64"] = "hex"


@router.post("/hmac")
async def hmac_text(
    body: _HMACBody,
    agent: Annotated[Agent, Depends(require_service_key_and_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    t0 = time.perf_counter()
    _check_size(body.text)
    err: str | None = None
    digest_str = ""
    try:
        h = _hmac.new(
            body.secret.encode("utf-8"),
            body.text.encode("utf-8"),
            getattr(hashlib, body.algorithm),
        )
        if body.encoding == "base64":
            digest_str = base64.b64encode(h.digest()).decode("ascii")
        else:
            digest_str = h.hexdigest()
    except Exception as e:
        err = "hmac_failed"
        raise HTTPException(
            status_code=400, detail={"error": "hmac_failed", "reason": str(e)}
        ) from e
    finally:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            ref = str(_uuid.uuid4())
            sc = await _charge(
                db, agent, amount=SC_COST["hmac"], tool="hmac", ref=ref
            )
            await _log_tool_call(
                db,
                agent_id=agent.id,
                tool_name="commons.crypto.hmac",
                input_summary={
                    "alg": body.algorithm,
                    "input_bytes": len(body.text.encode("utf-8")),
                    "encoding": body.encoding,
                },
                output_len=len(digest_str),
                sc_cost=sc,
                latency_ms=latency_ms,
                error=err,
            )
            await db.commit()
        except HTTPException:
            await db.rollback()
            raise
        except Exception:
            await db.rollback()
    return {
        "algorithm": body.algorithm,
        "encoding": body.encoding,
        "hmac": digest_str,
        "sc_charged": SC_COST["hmac"],
    }


# ── /password-gen (FREE) ──────────────────────────────────────────────────

class _PasswordGenBody(BaseModel):
    length: int = Field(16, ge=MIN_PASSWORD_LEN, le=MAX_PASSWORD_LEN)
    include_lower: bool = True
    include_upper: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = Field(
        False,
        description="Exclude visually ambiguous chars (0/O, 1/l/I, etc.).",
    )
    count: int = Field(1, ge=1, le=50, description="How many to generate.")


_AMBIGUOUS = set("0O1lI|`'\"{}[]()/\\,.;:")


def _alphabet(b: _PasswordGenBody) -> str:
    pools: list[str] = []
    if b.include_lower:
        pools.append(string.ascii_lowercase)
    if b.include_upper:
        pools.append(string.ascii_uppercase)
    if b.include_digits:
        pools.append(string.digits)
    if b.include_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?/")
    if not pools:
        raise HTTPException(
            status_code=400,
            detail={"error": "no_character_class_selected"},
        )
    alpha = "".join(pools)
    if b.exclude_ambiguous:
        alpha = "".join(c for c in alpha if c not in _AMBIGUOUS)
    if not alpha:
        raise HTTPException(
            status_code=400,
            detail={"error": "alphabet_empty_after_filters"},
        )
    # dedupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for c in alpha:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return "".join(out)


def _gen_one(alpha: str, length: int, b: _PasswordGenBody) -> str:
    """Generate one password, ensuring at least one char from each
    requested class (when length >= number of required classes)."""
    classes: list[str] = []
    if b.include_lower:
        classes.append(string.ascii_lowercase)
    if b.include_upper:
        classes.append(string.ascii_uppercase)
    if b.include_digits:
        classes.append(string.digits)
    if b.include_symbols:
        classes.append("!@#$%^&*()-_=+[]{};:,.<>?/")
    if b.exclude_ambiguous:
        classes = ["".join(c for c in cls if c not in _AMBIGUOUS) for cls in classes]
        classes = [c for c in classes if c]

    chars: list[str] = []
    if length >= len(classes):
        for cls in classes:
            chars.append(secrets.choice(cls))
    while len(chars) < length:
        chars.append(secrets.choice(alpha))
    # Fisher-Yates shuffle using secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


@router.post("/password-gen")
async def password_gen(body: _PasswordGenBody) -> dict:
    alpha = _alphabet(body)
    entropy_bits = round(body.length * math.log2(len(alpha)), 2)
    passwords = [_gen_one(alpha, body.length, body) for _ in range(body.count)]
    return {
        "passwords": passwords,
        "length": body.length,
        "alphabet_size": len(alpha),
        "entropy_bits": entropy_bits,
        "count": body.count,
        "sc_charged": 0.0,
    }


# ── /uuid ─────────────────────────────────────────────────────────────────

class _UUIDBody(BaseModel):
    version: Literal[1, 4, 5] = 4
    namespace: Literal["dns", "url", "oid", "x500"] | None = None
    name: str | None = Field(None, max_length=2048)
    count: int = Field(1, ge=1, le=100)


@router.post("/uuid")
async def gen_uuid(
    body: _UUIDBody,
    agent: Annotated[Agent, Depends(require_service_key_and_agent)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    t0 = time.perf_counter()
    err: str | None = None
    uuids: list[str] = []
    try:
        if body.version == 5:
            if not body.namespace or not body.name:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "v5_requires_namespace_and_name"},
                )
            ns = NAMESPACES[body.namespace]
            # v5 is deterministic given (ns, name); count > 1 yields duplicates.
            uuids = [str(_uuid.uuid5(ns, body.name)) for _ in range(body.count)]
        elif body.version == 1:
            uuids = [str(_uuid.uuid1()) for _ in range(body.count)]
        else:
            uuids = [str(_uuid.uuid4()) for _ in range(body.count)]
    except HTTPException:
        err = "uuid_failed"
        raise
    except Exception as e:
        err = "uuid_failed"
        raise HTTPException(
            status_code=400, detail={"error": "uuid_failed", "reason": str(e)}
        ) from e
    finally:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        try:
            ref = str(_uuid.uuid4())
            sc = await _charge(
                db, agent, amount=SC_COST["uuid"], tool="uuid", ref=ref
            )
            await _log_tool_call(
                db,
                agent_id=agent.id,
                tool_name="commons.crypto.uuid",
                input_summary={
                    "version": body.version,
                    "count": body.count,
                    "namespace": body.namespace,
                },
                output_len=sum(len(u) for u in uuids),
                sc_cost=sc,
                latency_ms=latency_ms,
                error=err,
            )
            await db.commit()
        except HTTPException:
            await db.rollback()
            raise
        except Exception:
            await db.rollback()
    return {
        "uuids": uuids,
        "version": body.version,
        "namespace": body.namespace,
        "count": body.count,
        "sc_charged": SC_COST["uuid"],
    }
