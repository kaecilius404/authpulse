"""Structured JSON output writer for scan results."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from authpulse.auth.authenticator import AuthSession
from authpulse.tester.models import TestResult


def _finding_to_dict(finding: TestResult) -> dict[str, Any]:
    snap = finding.snapshot
    return {
        "endpoint": finding.endpoint_url,
        "method": finding.method,
        "test_type": finding.test_type,
        "test_name": finding.test_name,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "description": finding.description,
        "evidence_curl": finding.evidence_curl,
        "remediation": finding.remediation,
        "response": {
            "status_code": snap.status_code if snap else None,
            "body_size": snap.body_size if snap else None,
            "response_keys": snap.response_keys if snap else [],
        } if snap else None,
        "extra": finding.extra,
    }


def write_json_report(
    target: str,
    sessions: dict[str, AuthSession],
    findings: list[TestResult],
    endpoints_tested: int,
    tests_performed: int,
    output_dir: str,
    scan_id: str | None = None,
) -> str:
    """Write a full scan report to *output_dir* and return the file path."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(tz=timezone.utc).isoformat()
    if not scan_id:
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"authpulse_{scan_id}.json"
    filepath = os.path.join(output_dir, filename)

    actual_findings = [f for f in findings if f.is_finding]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in actual_findings:
        sev = f.severity if f.severity in severity_counts else "info"
        severity_counts[sev] += 1

    auth_users: dict[str, Any] = {}
    for role_key, session in sessions.items():
        auth_users[role_key] = {
            "label": session.label,
            "email": session.email,
            "authenticated": session.authenticated,
            "endpoints_accessible": session.endpoints_accessible,
            "error": session.error,
        }

    report: dict[str, Any] = {
        "scan_info": {
            "target": target,
            "timestamp": timestamp,
            "scan_id": scan_id,
            "endpoints_tested": endpoints_tested,
            "tests_performed": tests_performed,
            "findings_total": len(actual_findings),
            "findings_critical": severity_counts["critical"],
            "findings_high": severity_counts["high"],
            "findings_medium": severity_counts["medium"],
            "findings_low": severity_counts["low"],
        },
        "authenticated_users": auth_users,
        "findings": [_finding_to_dict(f) for f in actual_findings],
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    return filepath


def write_markdown_report(
    target: str,
    sessions: dict[str, AuthSession],
    findings: list[TestResult],
    endpoints_tested: int,
    output_dir: str,
    scan_id: str | None = None,
) -> str:
    """Write a Markdown-formatted report and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    if not scan_id:
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"authpulse_{scan_id}.md"
    filepath = os.path.join(output_dir, filename)

    actual_findings = [f for f in findings if f.is_finding]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        actual_findings, key=lambda f: severity_order.get(f.severity, 5)
    )

    lines: list[str] = [
        f"# AuthPulse Scan Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Endpoints Tested:** {endpoints_tested}  ",
        f"**Total Findings:** {len(actual_findings)}",
        f"",
        f"---",
        f"",
        f"## Authentication",
        f"",
    ]
    for role_key, session in sessions.items():
        status = "✅ Authenticated" if session.authenticated else "❌ Failed"
        lines.append(f"- **{session.label}** (`{session.email}`): {status}")
        if session.error:
            lines.append(f"  - Error: {session.error}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    if not sorted_findings:
        lines.append("No findings detected. Manual validation still recommended.")
    else:
        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.severity.upper()
            lines.append(f"### [{sev}] {finding.method} `{finding.endpoint_url}`")
            lines.append(f"")
            lines.append(f"**Test Type:** {finding.test_type}  ")
            lines.append(f"**Test:** {finding.test_name}  ")
            lines.append(f"**Confidence:** {finding.confidence.upper()}")
            lines.append(f"")
            if finding.description:
                lines.append(f"**Description:**  ")
                lines.append(f"{finding.description}")
                lines.append(f"")
            if finding.evidence_curl:
                lines.append(f"**Evidence:**")
                lines.append(f"```bash")
                lines.append(finding.evidence_curl)
                lines.append(f"```")
                lines.append(f"")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return filepath
