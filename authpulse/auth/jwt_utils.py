"""JWT parsing, claims extraction, and test token generation."""

from __future__ import annotations

import base64
import json
import time
from typing import Any


def _b64_decode_padding(s: str) -> bytes:
    """Decode base64url with padding correction."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def parse_jwt(token: str) -> dict[str, Any] | None:
    """
    Parse a JWT without verification and return header + payload.

    Returns None if the string does not look like a JWT.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode_padding(parts[0]))
        payload = json.loads(_b64_decode_padding(parts[1]))
        return {"header": header, "payload": payload, "raw_parts": parts}
    except Exception:
        return None


def extract_claims(token: str) -> dict[str, Any]:
    """Return the JWT payload claims dict, or empty dict if unparseable."""
    parsed = parse_jwt(token)
    if parsed:
        return parsed["payload"]
    return {}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _build_unsigned_jwt(header: dict, payload: dict) -> str:
    """Build a JWT with an empty signature (alg:none style)."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


def make_expired_token(token: str) -> str | None:
    """
    Return a JWT copy with exp set 24 hours in the past.
    Uses alg:none so no signing key is required.
    Returns None if the token cannot be parsed.
    """
    parsed = parse_jwt(token)
    if not parsed:
        return None
    header = dict(parsed["header"])
    header["alg"] = "none"
    payload = dict(parsed["payload"])
    payload["exp"] = int(time.time()) - 86400
    return _build_unsigned_jwt(header, payload)


def make_role_modified_token(token: str, role_value: str = "admin") -> str | None:
    """
    Return a JWT copy with common role claims set to *role_value*.
    Tries the claim names: role, roles, user_role, type, scope, group.
    Uses alg:none.
    Returns None if the token cannot be parsed or no role claim is found.
    """
    parsed = parse_jwt(token)
    if not parsed:
        return None
    header = dict(parsed["header"])
    header["alg"] = "none"
    payload = dict(parsed["payload"])

    role_keys = ["role", "roles", "user_role", "type", "scope", "group", "permission"]
    modified = False
    for key in role_keys:
        if key in payload:
            original = payload[key]
            if isinstance(original, list):
                payload[key] = [role_value]
            else:
                payload[key] = role_value
            modified = True

    if not modified:
        # Inject a role claim even if one wasn't present
        payload["role"] = role_value
        modified = True

    return _build_unsigned_jwt(header, payload)


def make_malformed_token() -> str:
    """Return a clearly malformed token string."""
    return "eyJhbGciOiJub25lIn0.MALFORMED_PAYLOAD_AUTHPULSE_TEST."


def make_none_alg_token(token: str) -> str | None:
    """
    Return a JWT copy with alg changed to 'none' but original payload intact.
    Returns None if token cannot be parsed.
    """
    parsed = parse_jwt(token)
    if not parsed:
        return None
    header = dict(parsed["header"])
    header["alg"] = "none"
    payload = dict(parsed["payload"])
    return _build_unsigned_jwt(header, payload)


def is_jwt(token: str) -> bool:
    """Return True if the string looks like a JWT."""
    return parse_jwt(token) is not None
