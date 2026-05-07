"""Parameter manipulation tests: mass assignment, debug flags, field expansion."""

from __future__ import annotations

import re
from typing import Any

from authpulse.auth.authenticator import AuthSession
from authpulse.endpoints.loader import Endpoint
from authpulse.http_client import fetch
from authpulse.tester.models import ResponseSnapshot, TestResult

_ADMIN_PARAMS: list[tuple[str, str]] = [
    ("admin", "true"), ("is_admin", "1"), ("role", "administrator"),
    ("role", "admin"), ("superuser", "true"), ("elevated", "true"),
]
_DEBUG_PARAMS: list[tuple[str, str]] = [
    ("debug", "true"), ("verbose", "1"), ("internal", "true"), ("dev", "1"),
]
_INCLUDE_PARAMS: list[tuple[str, str]] = [
    ("include", "all"), ("include", "private,secret"), ("expand", "all"),
    ("expand", "private_data"), ("with", "all"),
]
_FIELDS_PARAMS: list[tuple[str, str]] = [
    ("fields", "*"), ("fields", "password,ssn,token"),
    ("select", "*"), ("columns", "all"),
]
_MASS_ASSIGN_KEYS: list[tuple[str, Any]] = [
    ("role", "admin"), ("role", "administrator"), ("is_admin", True),
    ("admin", True), ("user_type", "admin"), ("privilege_level", 100),
    ("permissions", ["admin", "write", "delete"]),
]


def _build_curl(method: str, url: str, headers: dict[str, str], note: str = "", body: dict | None = None) -> str:
    h = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    bd = f" -d '{body}'" if body else ""
    base = f"curl -s -X {method} {h}{bd} '{url}'"
    return f"# {note}\n{base}" if note else base


def _compare(baseline: ResponseSnapshot, test: ResponseSnapshot) -> tuple[bool, str]:
    if not test.is_success:
        return False, ""
    if not baseline.is_success:
        return True, f"Baseline was {baseline.status_code} but injection returned {test.status_code}"
    new_keys = set(test.response_keys) - set(baseline.response_keys)
    if new_keys:
        return True, f"New fields not in baseline: {', '.join(sorted(new_keys))}"
    if baseline.body_size > 0 and test.body_size > baseline.body_size * 1.5:
        return True, f"Response grew from {baseline.body_size} to {test.body_size} bytes"
    return False, ""


class ParamTester:
    """Tests parameter injection: mass assignment, debug flags, and field expansion."""

    def __init__(
        self,
        base_url: str,
        low_priv: AuthSession,
        high_priv: AuthSession,
        verify_ssl: bool,
        test_mass_assignment: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.low_priv = low_priv
        self.high_priv = high_priv
        self.verify_ssl = verify_ssl
        self.test_mass_assignment = test_mass_assignment

    def _full_url(self, path: str) -> str:
        return f"{self.base_url}{re.sub(r'{[^}]+}', '1', path)}"

    async def run(
        self,
        endpoint: Endpoint,
        baseline_high: ResponseSnapshot,
        baseline_low: ResponseSnapshot,
    ) -> list[TestResult]:
        results: list[TestResult] = []
        url = self._full_url(endpoint.normalised_url())
        for params, type_, name, sev in [
            (_ADMIN_PARAMS,   "admin_param",    "Admin parameter injection",          "medium"),
            (_DEBUG_PARAMS,   "debug_param",    "Debug parameter injection",           "low"),
            (_INCLUDE_PARAMS, "info_disclosure","Include/expand parameter injection",  "medium"),
            (_FIELDS_PARAMS,  "info_disclosure","Fields parameter injection",          "medium"),
        ]:
            results.extend(await self._test_qparams(endpoint, url, params, type_, name, sev, baseline_high, baseline_low))

        if self.test_mass_assignment and endpoint.method in {"POST", "PUT", "PATCH"}:
            results.extend(await self._test_mass_assign(endpoint, url, baseline_high, baseline_low))
        return results

    async def _test_qparams(
        self, endpoint: Endpoint, url: str,
        param_list: list[tuple[str, str]],
        test_type: str, name_prefix: str, default_sev: str,
        baseline_high: ResponseSnapshot, baseline_low: ResponseSnapshot,
    ) -> list[TestResult]:
        results: list[TestResult] = []
        for pk, pv in param_list:
            snap = await fetch(
                endpoint.method, url,
                self.low_priv.get_auth_headers(),
                self.low_priv.get_auth_cookies(),
                self.verify_ssl,
                params={pk: pv},
            )
            interesting, reason = _compare(baseline_low, snap)
            if not interesting and snap.is_success and baseline_high.is_success:
                high_keys = set(baseline_high.response_keys)
                low_keys = set(baseline_low.response_keys)
                snap_keys = set(snap.response_keys)
                new_from_high = snap_keys & high_keys - low_keys
                if new_from_high:
                    interesting = True
                    reason = f"Response now includes high-priv fields: {', '.join(sorted(new_from_high))}"
            if interesting:
                results.append(TestResult(
                    endpoint_url=endpoint.url, method=endpoint.method,
                    test_type=test_type, test_name=f"{name_prefix}: ?{pk}={pv}",
                    severity=default_sev, confidence="medium", is_finding=True,
                    description=f"?{pk}={pv} caused interesting response change. {reason}",
                    evidence_curl=_build_curl(endpoint.method, f"{url}?{pk}={pv}",
                                              self.low_priv.get_auth_headers(), f"{name_prefix}"),
                    remediation="Strip or validate unexpected query parameters server-side.",
                    snapshot=snap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
                ))
        return results

    async def _test_mass_assign(
        self, endpoint: Endpoint, url: str,
        baseline_high: ResponseSnapshot, baseline_low: ResponseSnapshot,
    ) -> list[TestResult]:
        results: list[TestResult] = []
        for fk, fv in _MASS_ASSIGN_KEYS:
            body = {**endpoint.body_template, fk: fv}
            snap = await fetch(
                endpoint.method, url,
                self.low_priv.get_auth_headers(),
                self.low_priv.get_auth_cookies(),
                self.verify_ssl,
                body=body,
            )
            interesting, reason = _compare(baseline_low, snap)
            if interesting:
                results.append(TestResult(
                    endpoint_url=endpoint.url, method=endpoint.method,
                    test_type="mass_assignment",
                    test_name=f"Mass assignment: {fk}={fv}",
                    severity="high", confidence="medium", is_finding=True,
                    description=f"Body injection '{fk}': '{fv}' caused interesting change. {reason}",
                    evidence_curl=_build_curl(endpoint.method, url,
                                              self.low_priv.get_auth_headers(),
                                              f"Mass assignment — {fk}={fv}", body=body),
                    remediation="Use an allowlist of accepted body fields. Never bind user-supplied role/permission fields directly.",
                    snapshot=snap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
                ))
        return results
