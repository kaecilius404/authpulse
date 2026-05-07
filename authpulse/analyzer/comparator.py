"""Response comparison and false positive reduction logic."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from authpulse.tester.models import ResponseSnapshot, TestResult

# Keys that commonly differ between users legitimately
_PERSONAL_KEYS = {
    "id", "user_id", "username", "name", "email", "created_at",
    "updated_at", "last_login", "profile_picture", "avatar",
}

# Patterns that suggest static/public resources
_STATIC_PATTERNS = [
    re.compile(r"\.(js|css|png|jpg|gif|svg|ico|woff|woff2|ttf|map)$", re.I),
    re.compile(r"/(static|assets|public|media)/"),
    re.compile(r"/(swagger|openapi|docs|health|ping|status)"),
]


@dataclass
class ComparisonResult:
    """Outcome of comparing two response snapshots."""

    is_same: bool
    is_similar: bool         # Same status, similar size
    is_interesting: bool     # Meaningful difference worth flagging
    reason: str
    confidence: str          # "high" | "medium" | "low"


class ResponseComparator:
    """Compares HTTP responses to identify authorization issues."""

    def compare(
        self,
        test_snap: ResponseSnapshot,
        baseline_high: ResponseSnapshot,
        baseline_low: ResponseSnapshot,
        endpoint_url: str = "",
    ) -> ComparisonResult:
        """
        Compare *test_snap* against both baselines.
        Returns a ComparisonResult indicating whether the test is interesting.
        """
        # Identical to high-priv → strong signal
        if (
            test_snap.body_hash == baseline_high.body_hash
            and test_snap.status_code == baseline_high.status_code
            and not (
                test_snap.body_hash == baseline_low.body_hash
                and test_snap.status_code == baseline_low.status_code
            )
        ):
            return ComparisonResult(
                is_same=True, is_similar=True, is_interesting=True,
                reason="Test response is identical to high-priv baseline",
                confidence="high",
            )

        # Test succeeded when low-priv was denied
        if test_snap.is_success and baseline_high.is_success and not baseline_low.is_success:
            return ComparisonResult(
                is_same=False, is_similar=False, is_interesting=True,
                reason=(
                    f"Test returned HTTP {test_snap.status_code} "
                    f"but low-priv baseline was {baseline_low.status_code}"
                ),
                confidence="high",
            )

        # New fields in response
        if test_snap.is_success and baseline_low.is_success:
            new_keys = set(test_snap.response_keys) - set(baseline_low.response_keys)
            # Filter out boring personal-data keys that always differ
            interesting_new = new_keys - _PERSONAL_KEYS
            if interesting_new:
                return ComparisonResult(
                    is_same=False, is_similar=True, is_interesting=True,
                    reason=f"Response includes new fields: {', '.join(sorted(interesting_new))}",
                    confidence="medium",
                )

        # Significant size increase
        if (
            test_snap.is_success
            and baseline_low.is_success
            and baseline_low.body_size > 0
            and test_snap.body_size > baseline_low.body_size * 2
        ):
            return ComparisonResult(
                is_same=False, is_similar=False, is_interesting=True,
                reason=(
                    f"Response size nearly doubled: "
                    f"{baseline_low.body_size} → {test_snap.body_size} bytes"
                ),
                confidence="low",
            )

        # Static resource detection
        for pat in _STATIC_PATTERNS:
            if pat.search(endpoint_url):
                return ComparisonResult(
                    is_same=False, is_similar=True, is_interesting=False,
                    reason="Static resource — differences expected",
                    confidence="low",
                )

        return ComparisonResult(
            is_same=False, is_similar=False, is_interesting=False,
            reason="No significant authorization difference detected",
            confidence="low",
        )

    def deduplicate(self, findings: list[TestResult]) -> list[TestResult]:
        """
        Remove near-duplicate findings (same endpoint + test_type).
        Keeps the highest-confidence/severity one.
        """
        seen: dict[str, TestResult] = {}
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        confidence_rank = {"high": 2, "medium": 1, "low": 0}

        for finding in findings:
            if not finding.is_finding:
                continue
            key = f"{finding.method}:{finding.endpoint_url}:{finding.test_type}"
            if key not in seen:
                seen[key] = finding
            else:
                existing = seen[key]
                if severity_rank.get(finding.severity, 0) > severity_rank.get(existing.severity, 0):
                    seen[key] = finding
                elif (
                    severity_rank.get(finding.severity, 0) == severity_rank.get(existing.severity, 0)
                    and confidence_rank.get(finding.confidence, 0)
                    > confidence_rank.get(existing.confidence, 0)
                ):
                    seen[key] = finding

        return list(seen.values())

    def reduce_false_positives(self, results: list[TestResult]) -> list[TestResult]:
        """
        Apply heuristics to downgrade likely false positives.
        """
        for result in results:
            if not result.is_finding:
                continue

            snap = result.snapshot
            if snap is None:
                continue

            # 404 on all IDs → static counter
            if snap.status_code == 404:
                result.is_finding = False
                continue

            # Tiny body (< 30 bytes) → probably just {"ok": true}
            if snap.body_size < 30:
                result.confidence = "low"

            # Endpoint returns same body for every request (hash collision across IDs)
            if (
                result.baseline_high_priv
                and result.baseline_low_priv
                and snap.body_hash == result.baseline_high_priv.body_hash
                == result.baseline_low_priv.body_hash
            ):
                result.confidence = "low"
                result.test_name += " [LIKELY FALSE POSITIVE: static response]"

        return results
