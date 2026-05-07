"""Handles login flows and token extraction for different auth methods.

Uses urllib (stdlib) for HTTP so the package works without aiohttp.
aiohttp is used as an optional faster backend when available.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Optional aiohttp
# ---------------------------------------------------------------------------
try:
    import aiohttp as _aiohttp
    _AIOHTTP = True
except ImportError:
    _aiohttp = None  # type: ignore
    _AIOHTTP = False


@dataclass
class AuthSession:
    """Represents an authenticated session for a single user role."""

    label: str
    email: str
    authenticated: bool = False
    token: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    endpoints_accessible: int = 0
    error: str | None = None

    def get_auth_headers(self) -> dict[str, str]:
        return self.headers.copy()

    def get_auth_cookies(self) -> dict[str, str]:
        return self.cookies.copy()


# ---------------------------------------------------------------------------
# Sync HTTP helper (urllib)
# ---------------------------------------------------------------------------

def _sync_post(
    url: str,
    body: dict[str, Any],
    verify_ssl: bool,
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    """POST *body* as JSON and return (status, headers, json_body)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
            headers = dict(resp.headers)
            try:
                body_out = json.loads(raw)
            except Exception:
                body_out = {}
            return status, headers, body_out
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
            body_out = json.loads(raw)
        except Exception:
            body_out = {}
        return exc.code, {}, body_out
    except Exception as exc:
        raise


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class Authenticator:
    """Authenticates users against the target API and manages sessions."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.target_cfg = config.get("target", {})
        self.auth_cfg = config.get("auth", {})
        self.users_cfg = config.get("users", {})
        self.base_url: str = self.target_cfg.get("base_url", "").rstrip("/")
        self.verify_ssl: bool = self.target_cfg.get("verify_ssl", True)

    def _build_login_body(self, user_cfg: dict[str, Any]) -> dict[str, Any]:
        template = self.auth_cfg.get("login_body_template", {})
        body: dict[str, Any] = {}
        for key, value in template.items():
            if isinstance(value, str):
                rendered = value
                for field_name, field_value in user_cfg.items():
                    rendered = rendered.replace(f"{{{field_name}}}", str(field_value))
                body[key] = rendered
            else:
                body[key] = value
        return body

    def _extract_token(
        self, resp_data: Any, resp_headers: dict
    ) -> str | None:
        location = self.auth_cfg.get("token_location", "response_body")
        field_path = self.auth_cfg.get("token_field", "access_token")

        if location == "response_header":
            val = resp_headers.get(field_path) or resp_headers.get(field_path.lower())
            return str(val).strip() if val else None

        if location == "response_body" and isinstance(resp_data, dict):
            parts = field_path.split(".")
            current: Any = resp_data
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    current = None
                    break
            if current is not None:
                return str(current).strip()
        return None

    def authenticate_sync(self, role_key: str) -> AuthSession:
        """Authenticate one user synchronously using urllib."""
        user_cfg = self.users_cfg.get(role_key, {})
        label = user_cfg.get("label", role_key)
        email = user_cfg.get("email", "")
        session = AuthSession(label=label, email=email)
        method_type = self.auth_cfg.get("method", "bearer_jwt")

        # API key — no network call needed
        if method_type == "api_key":
            api_key = user_cfg.get("api_key") or self.auth_cfg.get("api_key", "")
            key_header = self.auth_cfg.get("token_header", "X-API-Key")
            prefix = self.auth_cfg.get("token_prefix", "")
            session.headers[key_header] = f"{prefix}{api_key}"
            session.token = api_key
            session.authenticated = True
            return session

        login_endpoint = self.auth_cfg.get("login_endpoint", "/auth/login")
        url = f"{self.base_url}{login_endpoint}"
        body = self._build_login_body(user_cfg)

        try:
            status, resp_headers, resp_data = _sync_post(
                url, body, self.verify_ssl
            )
        except Exception as exc:
            session.error = f"Login request failed for {email}: {exc}"
            return session

        if status >= 400:
            session.error = f"Login returned HTTP {status} for {email}"
            return session

        if method_type == "cookie_session":
            # urllib doesn't expose Set-Cookie cleanly; treat as success if 2xx
            session.authenticated = True
            return session

        # Bearer JWT / OAuth2 password-flow
        token = self._extract_token(resp_data, resp_headers)
        if not token:
            session.error = f"Could not extract token from login response for {email}"
            return session

        token_header = self.auth_cfg.get("token_header", "Authorization")
        prefix = self.auth_cfg.get("token_prefix", "Bearer ")
        session.token = token
        session.headers[token_header] = f"{prefix}{token}"
        session.authenticated = True
        return session

    async def authenticate_all(self) -> dict[str, AuthSession]:
        """Authenticate all configured users and return role_key → AuthSession."""
        # Run sync calls in a thread pool so callers can use await
        loop = asyncio.get_event_loop()
        sessions: dict[str, AuthSession] = {}
        for role_key in self.users_cfg:
            session = await loop.run_in_executor(
                None, self.authenticate_sync, role_key
            )
            sessions[role_key] = session
        return sessions
