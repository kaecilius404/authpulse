"""Output package for AuthPulse."""
from authpulse.output.terminal import (
    print_banner,
    print_auth_status,
    print_baseline_summary,
    print_finding,
    print_progress,
    print_scan_start,
    print_summary,
    print_error,
    print_info,
    print_section,
    console,
)  # console is a thin _Console shim (no rich dependency)
from authpulse.output.json_writer import write_json_report, write_markdown_report

__all__ = [
    "print_banner",
    "print_auth_status",
    "print_baseline_summary",
    "print_finding",
    "print_progress",
    "print_scan_start",
    "print_summary",
    "print_error",
    "print_info",
    "print_section",
    "console",
    "write_json_report",
    "write_markdown_report",
]
