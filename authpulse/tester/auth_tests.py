"""Authorization tests: token removal, token swap, expiry, alg:none."""

from __future__ import annotations

from typing import Any

from authpulse.auth.authenticator import AuthSession
from authpulse.auth.jwt_utils import (
    is_jwt,
    make_expired_token,
    make_malformed_token,
    make_none_alg_token,
)
from authpulse.endpoints.loader import Endpoint
from authpulse.http_client import fetch
from authpulse.tester.models import ResponseSnapshot, TestResult

REMEDIATION_AUTH_BYPASS = (
    "Require authentication for this endpoint. Return 401 when no "
    "valid session/token is provided."
)
REMEDIATION_PRIV_ESC = (
    "Implement server-side role checks. Do not rely solely on client-supplied "
    "claims. Validate that the requesting user has the required role/permission."
)
REMEDIATION_TOKEN_VALIDATION = (
    "Validate token signature, algorithm, and expiry on every request. "
    "Reject tokens with alg:none, malformed payloads, or expired timestamps."
)


def _build_curl(method: str, url: str, headers: dict[str, str], note: str = "") -> str:
    h = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    base = f"curl -s -X {method} {h} '{url}'"
    return f"# {note}\n{base}" if note else base


def _full_url(base_url: str, endpoint: Endpoint) -> str:
    import re
    path = re.sub(r"\{[^}]+\}", "1", endpoint.normalised_url())
    return f"{base_url}{path}"


class AuthTester:
    """Runs authorization-focused tests against a single endpoint."""

    def __init__(
        self,
        base_url: str,
        low_priv: AuthSession,
        high_priv: AuthSession,
        verify_ssl: bool,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.low_priv = low_priv
        self.high_priv = high_priv
        self.verify_ssl = verify_ssl

    async def run_all(
        self,
        endpoint: Endpoint,
        baseline_high: ResponseSnapshot,
        baseline_low: ResponseSnapshot,
    ) -> list[TestResult]:
        url = _full_url(self.base_url, endpoint)
        results: list[TestResult] = []
        results.append(await self._test_no_token(endpoint, url, baseline_high))
        results.append(await self._test_low_priv_on_high_priv(endpoint, url, baseline_high, baseline_low))
        results.append(await self._test_malformed_token(endpoint, url, baseline_high))
        token = self.high_priv.token or ""
        if is_jwt(token):
            results.append(await self._test_expired_token(endpoint, url, baseline_high, token))
            results.append(await self._test_none_alg(endpoint, url, baseline_high, token))
        return [r for r in results if r is not None]

    async def _test_no_token(
        self, endpoint: Endpoint, url: str, baseline_high: ResponseSnapshot
    ) -> TestResult:
        snap = await fetch(endpoint.method, url, {}, {}, self.verify_ssl)
        is_finding = snap.is_success and baseline_high.is_success and snap.body_size > 50
        severity = "critical" if "admin" in endpoint.url.lower() else "high"
        return TestResult(
            endpoint_url=endpoint.url, method=endpoint.method,
            test_type="auth_bypass", test_name="No authentication token",
            severity=severity if is_finding else "info",
            confidence="high" if is_finding else "low",
            is_finding=is_finding,
            description=(
                f"Endpoint accessible without any authentication token. "
                f"Returned HTTP {snap.status_code} with {snap.body_size} bytes."
            ) if is_finding else "",
            evidence_curl=_build_curl(endpoint.method, url, {}, "No auth token") if is_finding else "",
            remediation=REMEDIATION_AUTH_BYPASS if is_finding else "",
            snapshot=snap, baseline_high_priv=baseline_high,
        )

    async def _test_low_priv_on_high_priv(
        self, endpoint: Endpoint, url: str,
        baseline_high: ResponseSnapshot, baseline_low: ResponseSnapshot,
    ) -> TestResult:
        snap = await fetch(
            endpoint.method, url,
            self.low_priv.get_auth_headers(),
            self.low_priv.get_auth_cookies(),
            self.verify_ssl,
        )
        is_finding = (
            snap.is_success and baseline_high.is_success
            and not baseline_low.is_success and snap.body_size > 20
        )
        same_body = (
            snap.body_hash == baseline_high.body_hash
            and snap.is_success and baseline_high.is_success
        )
        if same_body:
            is_finding = True
        severity = "critical" if "admin" in endpoint.url.lower() else "high"
        confidence = "high" if is_finding and (not baseline_low.is_success or same_body) else "medium"
        return TestResult(
            endpoint_url=endpoint.url, method=endpoint.method,
            test_type="privilege_escalation",
            test_name="Low-priv accessing high-priv endpoint",
            severity=severity if is_finding else "info",
            confidence=confidence,
            is_finding=is_finding,
            description=(
                f"Low-privilege user accessed restricted endpoint. "
                f"High-priv baseline: HTTP {baseline_high.status_code}. "
                f"Low-priv test: HTTP {snap.status_code} ({snap.body_size} bytes)."
            ) if is_finding else "",
            evidence_curl=_build_curl(
                endpoint.method, url, self.low_priv.get_auth_headers(),
                f"Low-priv ({self.low_priv.label}) on high-priv endpoint"
            ) if is_finding else "",
            remediation=REMEDIATION_PRIV_ESC if is_finding else "",
            snapshot=snap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
        )

    async def _test_malformed_token(
        self, endpoint: Endpoint, url: str, baseline_high: ResponseSnapshot
    ) -> TestResult:
        headers = {"Authorization": f"Bearer {make_malformed_token()}"}
        snap = await fetch(endpoint.method, url, headers, {}, self.verify_ssl)
        is_finding = snap.is_success and baseline_high.is_success and snap.body_size > 50
        return TestResult(
            endpoint_url=endpoint.url, method=endpoint.method,
            test_type="token_validation", test_name="Malformed token accepted",
            severity="high" if is_finding else "info",
            confidence="high" if is_finding else "low",
            is_finding=is_finding,
            description=f"Endpoint accepted a clearly malformed token. HTTP {snap.status_code}." if is_finding else "",
            evidence_curl=_build_curl(endpoint.method, url, headers, "Malformed JWT") if is_finding else "",
            remediation=REMEDIATION_TOKEN_VALIDATION if is_finding else "",
            snapshot=snap,
        )

    async def _test_expired_token(
        self, endpoint: Endpoint, url: str,
        baseline_high: ResponseSnapshot, token: str,
    ) -> TestResult:
        expired = make_expired_token(token)
        if not expired:
            return TestResult(endpoint_url=endpoint.url, method=endpoint.method,
                              test_type="token_validation", test_name="Expired token (skipped)",
                              severity="info", confidence="low")
        headers = {"Authorization": f"Bearer {expired}"}
        snap = await fetch(endpoint.method, url, headers, {}, self.verify_ssl)
        is_finding = snap.is_success and baseline_high.is_success and snap.body_size > 50
        return TestResult(
            endpoint_url=endpoint.url, method=endpoint.method,
            test_type="token_validation", test_name="Expired JWT accepted",
            severity="high" if is_finding else "info",
            confidence="high" if is_finding else "low",
            is_finding=is_finding,
            description=f"Endpoint accepted JWT with exp 24h in the past. HTTP {snap.status_code}." if is_finding else "",
            evidence_curl=_build_curl(endpoint.method, url, headers, "Expired JWT (alg:none)") if is_finding else "",
            remediation="Validate the exp claim on every request and reject expired tokens." if is_finding else "",
            snapshot=snap,
        )

    async def _test_none_alg(
        self, endpoint: Endpoint, url: str,
        baseline_high: ResponseSnapshot, token: str,
    ) -> TestResult:
        none_tok = make_none_alg_token(token)
        if not none_tok:
            return TestResult(endpoint_url=endpoint.url, method=endpoint.method,
                              test_type="jwt_none_alg", test_name="alg:none (skipped)",
                              severity="info", confidence="low")
        headers = {"Authorization": f"Bearer {none_tok}"}
        snap = await fetch(endpoint.method, url, headers, {}, self.verify_ssl)
        is_finding = snap.is_success and baseline_high.is_success and snap.body_size > 50
        return TestResult(
            endpoint_url=endpoint.url, method=endpoint.method,
            test_type="jwt_none_alg", test_name="JWT alg:none accepted",
            severity="critical" if is_finding else "info",
            confidence="high" if is_finding else "low",
            is_finding=is_finding,
            description="Endpoint accepted JWT with alg:none and no signature." if is_finding else "",
            evidence_curl=_build_curl(endpoint.method, url, headers, "JWT alg:none") if is_finding else "",
            remediation="Whitelist accepted JWT algorithms. Reject alg:none explicitly." if is_finding else "",
            snapshot=snap,
        )
