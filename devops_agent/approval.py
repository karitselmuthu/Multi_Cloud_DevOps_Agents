"""Approval tokens: the control plane mints one when a *different* human approves a specific plan; the MCP gateway
refuses every mutating call without a valid one. A token is bound to the request id and the plan hash, expires quickly,
and is single use (consumed in the DB by the gateway). Fails closed when APPROVAL_SECRET is missing or short.
ponytail: HMAC with a secret shared by the API and the executor. Move to asymmetric signing (KMS) when the gateway runs
in a different trust zone from the control plane."""
import base64
import hashlib
import hmac
import json
import os
import time
import uuid


class TokenInvalid(Exception):
    pass


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key():
    k = os.getenv("APPROVAL_SECRET", "")
    if len(k) < 16:
        raise TokenInvalid("APPROVAL_SECRET is not configured (min 16 chars)")
    return k.encode()


def _sign(body):
    return _b64(hmac.new(_key(), body.encode(), hashlib.sha256).digest())


def mint(rid, plan_hash, approver, ttl=600):
    body = _b64(json.dumps({"rid": rid, "ph": plan_hash, "sub": approver, "exp": time.time() + ttl, "jti": uuid.uuid4().hex}).encode())
    return f"{body}.{_sign(body)}"


def verify(token, rid, plan_hash):
    """Returns the claims, or raises TokenInvalid. Does NOT consume the token (the caller does, atomically)."""
    if not token or token.count(".") != 1:
        raise TokenInvalid("approval token required")
    body, sig = token.split(".")
    if not hmac.compare_digest(sig, _sign(body)):
        raise TokenInvalid("bad approval token signature")
    try:
        claims = json.loads(_unb64(body))
    except ValueError:
        raise TokenInvalid("malformed approval token")
    if claims["exp"] < time.time():
        raise TokenInvalid("approval token expired")
    if claims["rid"] != rid:
        raise TokenInvalid("approval token is for a different request")
    if claims["ph"] != plan_hash:
        raise TokenInvalid("plan changed since approval")
    return claims
