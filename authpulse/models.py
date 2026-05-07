"""Shared data models for test results and response snapshots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResponseSnapshot:
    """Captures key metrics from an HTTP response for comparison."""

    status_code: int
    body_hash: str
    body_size: int
    response_keys: list[str]       # top-level JSON keys, if body is JSON
    raw_body: str = ""             # first 4096 chars of body
    headers: dict[str, str] = field(default_factory=dict)
    is_json: bool = False
    json_body: Any = None

    @classmethod
    def from_response_data(
        cls,
        status: int,
        body: str,
        headers: dict[str, str],
    ) -> "ResponseSnapshot":
        body_bytes = body.encode("utf-8", errors="replace")
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        body_size = len(body_bytes)
        raw_body = body[:4096]
        json_body = None
        is_json = False
        keys: list[str] = []
        try:
            json_body = json.loads(body)
            is_json = True
            if isinstance(json_body, dict):
                keys = list(json_body.keys())
            elif isinstance(json_body, list) and json_body and isinstance(json_body[0], dict):
                keys = list(json_body[0].keys())
        except Exception:
            pass
        return cls(
            status_code=status,
            body_hash=body_hash,
            body_size=body_size,
            response_keys=keys,
            raw_body=raw_body,
            headers=headers,
            is_json=is_json,
            json_body=json_body,
        )

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_auth_error(self) -> bool:
        return self.status_code in {401, 403}

    @property
    def is_not_found(self) -> bool:
        return self.status_code == 404


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
