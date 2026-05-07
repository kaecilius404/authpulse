"""JWT-specific tests: role claim modification."""

from __future__ import annotations

import re

from authpulse.auth.authenticator import AuthSession
from authpulse.auth.jwt_utils import extract_claims, is_jwt, make_role_modified_token
from authpulse.endpoints.loader import Endpoint
from authpulse.http_client import fetch
from authpulse.tester.models import ResponseSnapshot, TestResult

REMEDIATION_ROLE_CLAIM = (
    "Do not trust role/permission claims from the token payload without server-side "
    "verification against an authoritative data store."
)


def _build_curl(method: str, url: str, headers: dict[str, str], note: str = "") -> str:
    h = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    base = f"curl -s -X {method} {h} '{url}'"
    return f"# {note}\n{base}" if note else base


class JWTTester:
    """Tests JWT-specific authorization flaws."""

    def __init__(
        self,
        base_url: str,
        low_priv: AuthSession,
        high_priv: AuthSession,
        verify_ssl: bool,
        test_role_manipulation: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.low_priv = low_priv
        self.high_priv = high_priv
        self.verify_ssl = verify_ssl
        self.test_role_manipulation = test_role_manipulation

    def _full_url(self, endpoint: Endpoint) -> str:
        path = re.sub(r"\{[^}]+\}", "1", endpoint.normalised_url())
        return f"{self.base_url}{path}"

    async def run(
        self,
        endpoint: Endpoint,
        baseline_high: ResponseSnapshot,
        baseline_low: ResponseSnapshot,
    ) -> list[TestResult]:
        if not self.test_role_manipulation:
            return []
        token = self.low_priv.token or ""
        if not is_jwt(token):
            return []
        return await self._test_role_escalation(endpoint, token, baseline_high, baseline_low)

    async def _test_role_escalation(
        self,
        endpoint: Endpoint,
        low_priv_token: str,
        baseline_high: ResponseSnapshot,
        baseline_low: ResponseSnapshot,
    ) -> list[TestResult]:
        url = self._full_url(endpoint)
        claims = extract_claims(low_priv_token)
        existing_auth = self.low_priv.headers.get("Authorization", "")
        prefix = "Bearer " if existing_auth.lower().startswith("bearer ") else ""

        for role_val in ["admin", "administrator", "superuser", "root", "ADMIN"]:
            modified = make_role_modified_token(low_priv_token, role_val)
            if not modified:
                continue
            headers = {**self.low_priv.get_auth_headers(), "Authorization": f"{prefix}{modified}"}
            snap = await fetch(endpoint.method, url, headers,
                               self.low_priv.get_auth_cookies(), self.verify_ssl)

            is_finding = (
                snap.is_success and baseline_high.is_success
                and not baseline_low.is_success and snap.body_size > 50
            ) or (snap.body_hash == baseline_high.body_hash and snap.is_success)

            if is_finding:
                severity = "critical" if "admin" in endpoint.url.lower() else "high"
                return [TestResult(
                    endpoint_url=endpoint.url, method=endpoint.method,
                    test_type="jwt_role_manipulation",
                    test_name=f"JWT role claim modified to '{role_val}'",
                    severity=severity, confidence="high", is_finding=True,
                    description=(
                        f"Changing the role claim to '{role_val}' in a low-priv JWT "
                        f"granted access to a high-privilege endpoint. "
                        f"Server accepted the unsigned (alg:none) token. "
                        f"Original claims: {list(claims.keys())}"
                    ),
                    evidence_curl=_build_curl(endpoint.method, url, headers,
                                              f"JWT role manipulation — role={role_val} (alg:none)"),
                    remediation=REMEDIATION_ROLE_CLAIM,
                    snapshot=snap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
                    extra={"original_claims": claims, "injected_role": role_val},
                )]
        return []
