"""Tester data models.

ResponseSnapshot is defined in authpulse.models (top-level) to avoid
circular imports with authpulse.http_client. This module re-exports it
and defines TestResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Re-export canonical location — all callers can use either import path
from authpulse.models import ResponseSnapshot  # noqa: F401


@dataclass
class TestResult:
    """Result of a single authorization test against one endpoint."""

    endpoint_url: str
    method: str
    test_type: str              # "auth_bypass", "idor", "privilege_escalation", etc.
    test_name: str              # human-readable description of the test variant
    severity: str               # "critical" | "high" | "medium" | "low" | "info"
    confidence: str             # "high" | "medium" | "low"
    is_finding: bool = False
    description: str = ""
    evidence_curl: str = ""
    remediation: str = ""
    snapshot: ResponseSnapshot | None = None
    baseline_high_priv: ResponseSnapshot | None = None
    baseline_low_priv: ResponseSnapshot | None = None
    extra: dict[str, Any] = field(default_factory=dict)
