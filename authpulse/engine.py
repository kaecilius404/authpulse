"""AuthPulse scan engine — orchestrates authentication, baseline collection, and testing."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from authpulse.auth.authenticator import AuthSession, Authenticator
from authpulse.endpoints.loader import Endpoint, EndpointLoader
from authpulse.http_client import fetch
from authpulse.tester.models import ResponseSnapshot, TestResult
from authpulse.tester.auth_tests import AuthTester
from authpulse.tester.idor_tests import IDORTester
from authpulse.tester.param_tests import ParamTester
from authpulse.tester.jwt_tests import JWTTester
from authpulse.analyzer.comparator import ResponseComparator
from authpulse.output import (
    print_banner,
    print_auth_status,
    print_baseline_summary,
    print_finding,
    print_scan_start,
    print_summary,
    print_error,
    print_info,
    write_json_report,
    write_markdown_report,
    console,
)

_DEFAULT_TESTS_PER_ENDPOINT = 12


@dataclass
class ScanConfig:
    target: dict[str, Any]
    auth: dict[str, Any]
    users: dict[str, Any]
    testing: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return self.target.get("base_url", "").rstrip("/")

    @property
    def verify_ssl(self) -> bool:
        return self.target.get("verify_ssl", True)

    @property
    def idor_cycling_count(self) -> int:
        return self.testing.get("idor_cycling_count", 20)

    @property
    def concurrent_requests(self) -> int:
        return max(1, self.testing.get("concurrent_requests", 5))

    @property
    def request_delay_ms(self) -> int:
        return self.testing.get("request_delay_ms", 200)

    @property
    def skip_static(self) -> bool:
        return self.testing.get("skip_static_files", True)

    @property
    def test_role_manipulation(self) -> bool:
        return self.testing.get("test_role_manipulation", True)

    @property
    def test_mass_assignment(self) -> bool:
        return self.testing.get("test_mass_assignment", True)

    @property
    def output_directory(self) -> str:
        return self.output.get("directory", "./authpulse-output")

    @property
    def output_format(self) -> str:
        return self.output.get("format", "json")

    @property
    def verbose(self) -> bool:
        return self.output.get("verbose", False)

    @property
    def low_priv_key(self) -> str:
        return "low_priv"

    @property
    def high_priv_key(self) -> str:
        return "high_priv"


def _build_full_url(base_url: str, endpoint: Endpoint) -> str:
    import re
    path = re.sub(r"\{[^}]+\}", "1", endpoint.normalised_url())
    return f"{base_url}{path}"


class ScanEngine:
    """Main orchestration class for an AuthPulse scan."""

    def __init__(
        self,
        config: dict[str, Any],
        verbose: bool = False,
        quick: bool = False,
        on_finding: Callable[[TestResult], None] | None = None,
    ) -> None:
        self.cfg = ScanConfig(
            target=config.get("target", {}),
            auth=config.get("auth", {}),
            users=config.get("users", {}),
            testing=config.get("testing", {}),
            output=config.get("output", {}),
        )
        self.verbose = verbose or self.cfg.verbose
        self.quick = quick
        self.on_finding = on_finding or self._default_on_finding
        self._comparator = ResponseComparator()
        self._all_results: list[TestResult] = []
        self._tests_performed = 0

    def _default_on_finding(self, finding: TestResult) -> None:
        print_finding(finding)

    async def run(self, endpoints: list[Endpoint]) -> list[TestResult]:
        """Run the full scan and return all findings."""
        start_time = time.monotonic()
        print_banner(self.cfg.base_url)

        # ── Phase 1: Authenticate ──────────────────────────────────────────
        print_info("Authenticating users...")
        authenticator = Authenticator({
            "target": self.cfg.target,
            "auth": self.cfg.auth,
            "users": self.cfg.users,
        })
        sessions = await authenticator.authenticate_all()
        print_auth_status(sessions)

        low_priv = sessions.get(self.cfg.low_priv_key)
        high_priv = sessions.get(self.cfg.high_priv_key)

        if not low_priv or not low_priv.authenticated:
            print_error(
                f"Low-priv user authentication failed: "
                f"{low_priv.error if low_priv else 'user not configured'}"
            )
            return []
        if not high_priv or not high_priv.authenticated:
            print_error(
                f"High-priv user authentication failed: "
                f"{high_priv.error if high_priv else 'user not configured'}"
            )
            return []

        delay = self.cfg.request_delay_ms / 1000.0
        semaphore = asyncio.Semaphore(self.cfg.concurrent_requests)

        # ── Phase 2: Baseline collection ──────────────────────────────────
        print_info("Collecting baselines...")
        high_baselines: dict[str, ResponseSnapshot] = {}
        low_baselines: dict[str, ResponseSnapshot] = {}

        for ep in endpoints:
            url = _build_full_url(self.cfg.base_url, ep)
            key = f"{ep.method}:{ep.url}"

            high_snap = await fetch(
                ep.method, url,
                high_priv.get_auth_headers(),
                high_priv.get_auth_cookies(),
                self.cfg.verify_ssl,
            )
            high_baselines[key] = high_snap
            if high_snap.is_success:
                high_priv.endpoints_accessible += 1

            low_snap = await fetch(
                ep.method, url,
                low_priv.get_auth_headers(),
                low_priv.get_auth_cookies(),
                self.cfg.verify_ssl,
            )
            low_baselines[key] = low_snap
            if low_snap.is_success:
                low_priv.endpoints_accessible += 1

            await asyncio.sleep(delay)

        print_baseline_summary(
            self.cfg.high_priv_key, high_priv.label,
            high_priv.endpoints_accessible, len(endpoints)
        )
        print_baseline_summary(
            self.cfg.low_priv_key, low_priv.label,
            low_priv.endpoints_accessible, len(endpoints)
        )

        # ── Phase 3: Build testers ─────────────────────────────────────────
        auth_tester = AuthTester(
            self.cfg.base_url, low_priv, high_priv, self.cfg.verify_ssl
        )
        idor_tester = IDORTester(
            self.cfg.base_url, low_priv, high_priv,
            self.cfg.verify_ssl, self.cfg.idor_cycling_count,
        )
        param_tester = ParamTester(
            self.cfg.base_url, low_priv, high_priv,
            self.cfg.verify_ssl, self.cfg.test_mass_assignment,
        )
        jwt_tester = JWTTester(
            self.cfg.base_url, low_priv, high_priv,
            self.cfg.verify_ssl, self.cfg.test_role_manipulation,
        )

        # ── Phase 4: Test matrix ──────────────────────────────────────────
        print_scan_start(len(endpoints), _DEFAULT_TESTS_PER_ENDPOINT)

        tasks = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            tasks.append(
                self._test_endpoint(
                    ep,
                    high_baselines.get(key, ResponseSnapshot.from_response_data(0, "", {})),
                    low_baselines.get(key, ResponseSnapshot.from_response_data(0, "", {})),
                    auth_tester, idor_tester, param_tester, jwt_tester,
                    semaphore, delay,
                )
            )

        completed = 0
        for coro in asyncio.as_completed(tasks):
            results = await coro
            self._all_results.extend(results)
            completed += 1

        # ── Phase 5: Post-process & report ────────────────────────────────
        print("")  # newline after progress
        findings = self._comparator.reduce_false_positives(self._all_results)
        findings = [f for f in findings if f.is_finding]
        findings = self._comparator.deduplicate(findings)

        import datetime
        scan_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = write_json_report(
            target=self.cfg.base_url,
            sessions=sessions,
            findings=findings,
            endpoints_tested=len(endpoints),
            tests_performed=self._tests_performed,
            output_dir=self.cfg.output_directory,
            scan_id=scan_id,
        )
        if self.cfg.output_format in ("markdown", "md"):
            write_markdown_report(
                target=self.cfg.base_url,
                sessions=sessions,
                findings=findings,
                endpoints_tested=len(endpoints),
                output_dir=self.cfg.output_directory,
                scan_id=scan_id,
            )

        elapsed = time.monotonic() - start_time
        print_summary(
            target=self.cfg.base_url,
            endpoints_tested=len(endpoints),
            tests_performed=self._tests_performed,
            findings=findings,
            elapsed_seconds=elapsed,
            output_path=json_path,
        )

        return findings

    async def _test_endpoint(
        self,
        endpoint: Endpoint,
        baseline_high: ResponseSnapshot,
        baseline_low: ResponseSnapshot,
        auth_tester: AuthTester,
        idor_tester: IDORTester,
        param_tester: ParamTester,
        jwt_tester: JWTTester,
        semaphore: asyncio.Semaphore,
        delay: float,
    ) -> list[TestResult]:
        results: list[TestResult] = []

        async with semaphore:
            auth_results = await auth_tester.run_all(endpoint, baseline_high, baseline_low)
            results.extend(auth_results)
            self._tests_performed += len(auth_results)
            await asyncio.sleep(delay)

            if not self.quick:
                jwt_results = await jwt_tester.run(endpoint, baseline_high, baseline_low)
                results.extend(jwt_results)
                self._tests_performed += len(jwt_results)
                await asyncio.sleep(delay)

            if not self.quick and (endpoint.has_id_param or endpoint.params):
                idor_results = await idor_tester.run(endpoint, baseline_low, baseline_high)
                results.extend(idor_results)
                self._tests_performed += len(idor_results)
                await asyncio.sleep(delay)

            if not self.quick:
                param_results = await param_tester.run(endpoint, baseline_high, baseline_low)
                results.extend(param_results)
                self._tests_performed += len(param_results)
                await asyncio.sleep(delay)

        for result in results:
            if result.is_finding:
                self.on_finding(result)

        return results
