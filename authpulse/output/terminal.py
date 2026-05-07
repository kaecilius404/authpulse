"""Real-time terminal output using colorama (stdlib fallback if unavailable)."""

from __future__ import annotations

import re
import sys
from typing import Any

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class _Noop:
        def __getattr__(self, _): return ""
    Fore = Style = _Noop()  # type: ignore

from authpulse.tester.models import TestResult

_W    = Style.RESET_ALL if _HAS_COLOR else ""
_DIM  = Style.DIM       if _HAS_COLOR else ""
_BOLD = Style.BRIGHT    if _HAS_COLOR else ""
_CYAN = Fore.CYAN       if _HAS_COLOR else ""
_GRN  = Fore.GREEN      if _HAS_COLOR else ""
_RED  = Fore.RED        if _HAS_COLOR else ""
_YLW  = Fore.YELLOW     if _HAS_COLOR else ""

_SEVERITY_COLORS = {
    "critical": Fore.RED + Style.BRIGHT if _HAS_COLOR else "",
    "high":     Fore.RED                if _HAS_COLOR else "",
    "medium":   Fore.YELLOW             if _HAS_COLOR else "",
    "low":      Fore.CYAN               if _HAS_COLOR else "",
    "info":     Style.DIM               if _HAS_COLOR else "",
}

_SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

_MARKUP_RE = re.compile(r"\[/?[^\[\]]*\]")


def _p(text: str = "") -> None:
    print(_MARKUP_RE.sub("", text))


# Thin console shim so output/__init__.py can re-export `console`
class _Console:
    def print(self, text: str = "", end: str = "\n", **_kwargs: Any) -> None:
        print(_MARKUP_RE.sub("", str(text)), end=end)


console = _Console()


# ─────────────────────────────────────────────────────────────────────────────

def print_banner(target: str) -> None:
    _p()
    _p(f"{_BOLD}{_CYAN}  AuthPulse — Authorization Testing Framework{_W}")
    _p(f"  {_DIM}Target:{_W} {_CYAN}{target}{_W}")
    _p()


def print_auth_status(sessions: dict) -> None:
    _p(f"{_BOLD}Authentication Status{_W}")
    for role_key, session in sessions.items():
        icon  = "✅" if session.authenticated else "❌"
        color = _GRN if session.authenticated else _RED
        label = session.label or role_key
        err   = f"  {_RED}— {session.error}{_W}" if session.error else ""
        _p(f"  {icon} {color}{label}{_W} {_DIM}({session.email}){_W}{err}")
    _p()


def print_baseline_summary(role_key: str, label: str, accessible: int, total: int) -> None:
    _p(
        f"  {_DIM}BASELINE{_W}  {_CYAN}{label}{_W}: "
        f"{_BOLD}{accessible}{_W}/{total} endpoints accessible"
    )


def print_scan_start(endpoint_count: int, test_count: int) -> None:
    _p()
    _p(f"{_BOLD}Scan Starting{_W}  "
       f"{_DIM}{endpoint_count} endpoints × ~{test_count} tests each{_W}")
    _p(_DIM + "─" * 60 + _W)
    _p()


def print_finding(finding: TestResult) -> None:
    color = _SEVERITY_COLORS.get(finding.severity, "")
    icon  = _SEVERITY_ICONS.get(finding.severity, "•")
    sev   = finding.severity.upper()

    _p(f"{icon} {color}[{sev}]{_W} {_BOLD}{finding.method}{_W} {finding.endpoint_url}")
    if finding.description:
        _p(f"     {_DIM}{finding.description}{_W}")
    if finding.confidence:
        _p(f"     {_DIM}Confidence: {finding.confidence.upper()}{_W}")
    if finding.evidence_curl:
        lines   = finding.evidence_curl.splitlines()
        cmd_line = next((l for l in lines if not l.startswith("#")), "")
        if len(cmd_line) > 100:
            cmd_line = cmd_line[:97] + "..."
        _p(f"     {_DIM}{_CYAN}$ {cmd_line}{_W}")
    _p()


def print_progress(current: int, total: int, endpoint: str, test: str) -> None:
    pct    = int((current / total) * 100) if total > 0 else 0
    filled = int(30 * pct / 100)
    bar    = "█" * filled + "░" * (30 - filled)
    short  = endpoint[-40:] if len(endpoint) > 40 else endpoint
    print(
        f"\r  [{bar}] {pct:3d}% [{current}/{total}] {short} — {test}",
        end="",
        flush=True,
    )


def print_summary(
    target: str,
    endpoints_tested: int,
    tests_performed: int,
    findings: list[TestResult],
    elapsed_seconds: float,
    output_path: str | None = None,
) -> None:
    _p()
    _p(_DIM + "─" * 60 + _W)
    _p()

    actual = [f for f in findings if f.is_finding]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in actual:
        if f.severity in counts:
            counts[f.severity] += 1

    _p(f"{_BOLD}Scan Summary{_W}")
    _p(f"  {'Target':<26} {target}")
    _p(f"  {'Endpoints Tested':<26} {endpoints_tested}")
    _p(f"  {'Tests Performed':<26} {tests_performed}")
    _p(f"  {'Total Findings':<26} {len(actual)}")
    _p(f"  {'Critical':<26} {_RED}{_BOLD}{counts['critical']}{_W}")
    _p(f"  {'High':<26} {_RED}{counts['high']}{_W}")
    _p(f"  {'Medium':<26} {_YLW}{counts['medium']}{_W}")
    _p(f"  {'Low':<26} {_CYAN}{counts['low']}{_W}")
    _p(f"  {'Duration':<26} {elapsed_seconds:.1f}s")

    if actual:
        _p()
        _p(f"{_BOLD}Findings by Category{_W}")
        cats: dict[str, int] = {}
        for f in actual:
            cats[f.test_type] = cats.get(f.test_type, 0) + 1
        for cat, cnt in sorted(cats.items(), key=lambda x: -x[1]):
            _p(f"  {_DIM}{cat:<30}{_W} {cnt}")

    if output_path:
        _p()
        _p(f"{_DIM}Results saved to:{_W} {_CYAN}{output_path}{_W}")
    _p()


def print_error(message: str) -> None:
    print(f"{_RED}{_BOLD}ERROR:{_W} {message}", file=sys.stderr)


def print_info(message: str) -> None:
    _p(f"{_DIM}{message}{_W}")


def print_section(title: str) -> None:
    _p()
    _p(f"{_BOLD}{title}{_W}")
    _p(_DIM + "─" * len(title) + _W)
