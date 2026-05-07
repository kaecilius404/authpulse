"""IDOR tests: ID cycling, UUID manipulation, cross-user resource access."""

from __future__ import annotations

import re
import uuid
from typing import Any

from authpulse.auth.authenticator import AuthSession
from authpulse.endpoints.loader import Endpoint
from authpulse.http_client import fetch
from authpulse.tester.models import ResponseSnapshot, TestResult

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_INT_ID_RE = re.compile(r"/(\d+)(/|$|\?)")

REMEDIATION_IDOR = (
    "Add server-side ownership checks. Verify the authenticated user owns or "
    "has explicit permission to access the requested resource ID before returning data."
)

_PII_FIELDS = {
    "ssn", "last_4_ssn", "social_security", "credit_card", "card_number",
    "cvv", "password", "password_hash", "hashed_password", "token", "secret",
    "private_key", "api_key", "dob", "date_of_birth", "phone", "address",
    "bank_account", "routing_number", "passport",
}


def _detect_pii_keys(keys: list[str]) -> list[str]:
    found = []
    for k in keys:
        if k.lower() in _PII_FIELDS or any(p in k.lower() for p in ["ssn", "password", "secret", "token", "card"]):
            found.append(k)
    return found


def _substitute_int_id(url: str, new_id: str) -> str:
    return _INT_ID_RE.sub(f"/{new_id}\\2", url, count=1)


def _substitute_uuid(url: str, new_uuid: str) -> str:
    return _UUID_RE.sub(new_uuid, url, count=1)


def _build_curl(method: str, url: str, headers: dict[str, str], note: str = "") -> str:
    h = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
    base = f"curl -s -X {method} {h} '{url}'"
    return f"# {note}\n{base}" if note else base


class IDORTester:
    """Cycles through resource IDs to detect insecure direct object references."""

    def __init__(
        self,
        base_url: str,
        low_priv: AuthSession,
        high_priv: AuthSession,
        verify_ssl: bool,
        cycling_count: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.low_priv = low_priv
        self.high_priv = high_priv
        self.verify_ssl = verify_ssl
        self.cycling_count = cycling_count

    def _full_url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _id_type(self, endpoint: Endpoint) -> str:
        url = endpoint.url
        if _UUID_RE.search(url):
            return "uuid"
        for param in endpoint.params:
            if "uuid" in param.lower():
                return "uuid"
            if "id" in param.lower():
                return "int"
        if _INT_ID_RE.search(url):
            return "int"
        if endpoint.params:
            return "int"
        return "none"

    def _int_candidates(self, original: int) -> list[str]:
        base = list(range(1, min(self.cycling_count + 1, 21)))
        for extra in [0, -1, 99999, 2147483647]:
            if extra not in base:
                base.append(extra)
        return [str(i) for i in base if i != original]

    def _uuid_variants(self, original: str) -> list[str]:
        variants = [
            "00000000-0000-0000-0000-000000000000",
            str(uuid.uuid4()), str(uuid.uuid4()),
        ]
        chars = list(original.replace("-", ""))
        if chars:
            chars[-1] = "f" if chars[-1] != "f" else "0"
            rebuilt = (
                "".join(chars[:8]) + "-" + "".join(chars[8:12]) + "-" +
                "".join(chars[12:16]) + "-" + "".join(chars[16:20]) + "-" +
                "".join(chars[20:])
            )
            variants.append(rebuilt)
        return [v for v in variants if v != original]

    async def run(
        self,
        endpoint: Endpoint,
        baseline_low: ResponseSnapshot,
        baseline_high: ResponseSnapshot,
    ) -> list[TestResult]:
        id_type = self._id_type(endpoint)
        if id_type == "none" and not endpoint.has_id_param:
            return []
        results: list[TestResult] = []
        tpl = endpoint.normalised_url()
        if id_type == "uuid":
            results.extend(await self._test_uuid(endpoint, tpl, baseline_low, baseline_high))
        else:
            results.extend(await self._test_int(endpoint, tpl, baseline_low, baseline_high))
        if endpoint.params and id_type == "int":
            results.extend(await self._test_usernames(endpoint, tpl, baseline_low))
        return results

    async def _test_int(self, endpoint: Endpoint, tpl: str,
                        baseline_low: ResponseSnapshot, baseline_high: ResponseSnapshot) -> list[TestResult]:
        original_id = 1
        m = _INT_ID_RE.search(endpoint.url)
        if m:
            try:
                original_id = int(m.group(1))
            except ValueError:
                pass

        successful: list[tuple[str, ResponseSnapshot]] = []
        for test_id in self._int_candidates(original_id):
            path = re.sub(r"\{[^}]+\}", test_id, tpl, count=1)
            if not re.search(r"/\d+", path):
                path = _substitute_int_id(path, test_id)
            snap = await fetch(
                endpoint.method, self._full_url(path),
                self.low_priv.get_auth_headers(),
                self.low_priv.get_auth_cookies(),
                self.verify_ssl,
            )
            if snap.is_success and snap.body_size > 50:
                successful.append((test_id, snap))

        if not successful:
            return []

        if len(successful) >= 3:
            tid, tsnap = successful[0]
            pii = _detect_pii_keys(tsnap.response_keys)
            sample_path = re.sub(r"\{[^}]+\}", tid, tpl, count=1)
            return [TestResult(
                endpoint_url=endpoint.url, method=endpoint.method,
                test_type="idor",
                test_name=f"IDOR: {len(successful)}/{len(self._int_candidates(original_id))} IDs accessible",
                severity="high" if pii else "medium",
                confidence="high", is_finding=True,
                description=(
                    f"Low-privilege user accessed {len(successful)} resource IDs. "
                    + (f"Response includes PII fields: {', '.join(pii)}." if pii else "")
                ),
                evidence_curl=_build_curl(
                    endpoint.method, self._full_url(sample_path),
                    self.low_priv.get_auth_headers(), f"IDOR — low-priv accessing ID {tid}"
                ),
                remediation=REMEDIATION_IDOR,
                snapshot=tsnap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
                extra={"accessible_ids": [i for i, _ in successful]},
            )]

        # Single access but was blocked in baseline
        if not baseline_low.is_success:
            tid, tsnap = successful[0]
            sample_path = re.sub(r"\{[^}]+\}", tid, tpl, count=1)
            return [TestResult(
                endpoint_url=endpoint.url, method=endpoint.method,
                test_type="idor", test_name=f"Possible IDOR: accessed ID {tid}",
                severity="medium", confidence="medium", is_finding=True,
                description=f"Low-privilege user accessed resource ID={tid} that should require higher permissions.",
                evidence_curl=_build_curl(
                    endpoint.method, self._full_url(sample_path),
                    self.low_priv.get_auth_headers(), f"Possible IDOR — ID {tid}"
                ),
                remediation=REMEDIATION_IDOR,
                snapshot=tsnap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
            )]
        return []

    async def _test_uuid(self, endpoint: Endpoint, tpl: str,
                         baseline_low: ResponseSnapshot, baseline_high: ResponseSnapshot) -> list[TestResult]:
        m = _UUID_RE.search(endpoint.url)
        original_uuid = m.group(0) if m else ""
        successful: list[tuple[str, ResponseSnapshot]] = []
        for variant in self._uuid_variants(original_uuid):
            path = endpoint.url.replace(original_uuid, variant) if original_uuid else re.sub(r"\{[^}]+\}", variant, tpl, count=1)
            snap = await fetch(
                endpoint.method, self._full_url(path),
                self.low_priv.get_auth_headers(),
                self.low_priv.get_auth_cookies(),
                self.verify_ssl,
            )
            if snap.is_success and snap.body_size > 50:
                successful.append((variant, snap))
        if not successful:
            return []
        vid, vsnap = successful[0]
        pii = _detect_pii_keys(vsnap.response_keys)
        spath = endpoint.url.replace(original_uuid, vid) if original_uuid else tpl
        return [TestResult(
            endpoint_url=endpoint.url, method=endpoint.method,
            test_type="idor", test_name=f"UUID IDOR: {len(successful)} variants accessible",
            severity="high" if pii else "medium", confidence="medium", is_finding=True,
            description=(
                f"Low-privilege user accessed {len(successful)} UUID-based resources. "
                + (f"PII fields: {', '.join(pii)}." if pii else "")
            ),
            evidence_curl=_build_curl(endpoint.method, self._full_url(spath),
                                       self.low_priv.get_auth_headers(), "UUID IDOR test"),
            remediation=REMEDIATION_IDOR,
            snapshot=vsnap, baseline_high_priv=baseline_high, baseline_low_priv=baseline_low,
        )]

    async def _test_usernames(self, endpoint: Endpoint, tpl: str,
                               baseline_low: ResponseSnapshot) -> list[TestResult]:
        known = ["admin", "root", "test", "administrator", "superuser", "system", "guest"]
        findings: list[TestResult] = []
        for username in known:
            path = re.sub(r"\{[^}]+\}", username, tpl, count=1)
            snap = await fetch(
                endpoint.method, self._full_url(path),
                self.low_priv.get_auth_headers(),
                self.low_priv.get_auth_cookies(),
                self.verify_ssl,
            )
            if snap.is_success and snap.body_size > 50 and not baseline_low.is_success:
                findings.append(TestResult(
                    endpoint_url=endpoint.url, method=endpoint.method,
                    test_type="idor", test_name=f"Username IDOR: '{username}'",
                    severity="medium", confidence="medium", is_finding=True,
                    description=f"Low-privilege user accessed resource for username '{username}'.",
                    evidence_curl=_build_curl(endpoint.method, self._full_url(path),
                                              self.low_priv.get_auth_headers(), f"Username IDOR — '{username}'"),
                    remediation=REMEDIATION_IDOR,
                    snapshot=snap, baseline_low_priv=baseline_low,
                ))
        return findings
