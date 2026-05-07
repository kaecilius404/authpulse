"""AuthPulse command-line interface."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import click
import yaml

from authpulse.endpoints.loader import Endpoint, EndpointLoader
from authpulse.engine import ScanEngine
from authpulse.auth.authenticator import Authenticator
from authpulse.auth.jwt_utils import (
    parse_jwt,
    extract_claims,
    make_expired_token,
    make_role_modified_token,
    make_none_alg_token,
    make_malformed_token,
)
from authpulse.output import print_error, print_info, console


def _load_config(config_path: str) -> dict[str, Any]:
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except FileNotFoundError:
        print_error(f"Config file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as exc:
        print_error(f"Invalid YAML in config: {exc}")
        sys.exit(1)


def _load_endpoints(
    endpoints_file: str | None,
    endpoint: str | None,
    method: str,
    skip_static: bool,
) -> list[Endpoint]:
    loader = EndpointLoader(skip_static=skip_static)

    if endpoint:
        # Single endpoint provided via --endpoint flag
        return loader.load_from_list([{"url": endpoint, "method": method}])

    if endpoints_file:
        try:
            return loader.load(endpoints_file)
        except FileNotFoundError:
            print_error(f"Endpoints file not found: {endpoints_file}")
            sys.exit(1)
        except Exception as exc:
            print_error(f"Could not parse endpoints file: {exc}")
            sys.exit(1)

    print_error("Provide --endpoints or --endpoint.")
    sys.exit(1)


@click.group()
@click.version_option("1.0.0", prog_name="authpulse")
def main() -> None:
    """AuthPulse — Authorization Testing Framework for Bug Bounty Hunting."""


# ──────────────────────────────────────────────────────────────────────────────
# scan command
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--config", "-c", required=True, help="Path to config.yaml")
@click.option("--endpoints", "-e", default=None, help="Path to endpoints JSON/text file")
@click.option("--endpoint", default=None, help="Single endpoint path to test (e.g. /api/v1/users)")
@click.option("--method", "-m", default="GET", show_default=True, help="HTTP method for single endpoint")
@click.option("--output", "-o", default=None, help="Output directory (overrides config)")
@click.option("--verbose", "-v", is_flag=True, help="Show all tests, not just findings")
@click.option("--quick", "-q", is_flag=True, help="Quick mode: auth tests only, no IDOR/param cycling")
def scan(
    config: str,
    endpoints: str | None,
    endpoint: str | None,
    method: str,
    output: str | None,
    verbose: bool,
    quick: bool,
) -> None:
    """Run a full authorization test scan."""
    cfg = _load_config(config)
    if output:
        cfg.setdefault("output", {})["directory"] = output

    skip_static = cfg.get("testing", {}).get("skip_static_files", True)
    ep_list = _load_endpoints(endpoints, endpoint, method, skip_static)

    if not ep_list:
        print_error("No endpoints loaded. Check your endpoints file.")
        sys.exit(1)

    print_info(f"Loaded {len(ep_list)} endpoint(s).")

    engine = ScanEngine(cfg, verbose=verbose, quick=quick)
    findings = asyncio.run(engine.run(ep_list))
    critical_high = sum(1 for f in findings if f.severity in ("critical", "high"))
    sys.exit(1 if critical_high > 0 else 0)


# ──────────────────────────────────────────────────────────────────────────────
# idor command
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--config", "-c", required=True, help="Path to config.yaml")
@click.option("--endpoints", "-e", required=True, help="Path to endpoints file")
@click.option("--output", "-o", default=None, help="Output directory")
def idor(config: str, endpoints: str, output: str | None) -> None:
    """Run IDOR tests only."""
    cfg = _load_config(config)
    if output:
        cfg.setdefault("output", {})["directory"] = output

    # Disable non-IDOR tests via a trimmed config copy
    cfg.setdefault("testing", {})
    skip_static = cfg["testing"].get("skip_static_files", True)
    ep_list = _load_endpoints(endpoints, None, "GET", skip_static)

    if not ep_list:
        print_error("No endpoints loaded.")
        sys.exit(1)

    print_info(f"Loaded {len(ep_list)} endpoint(s) — IDOR mode only.")

    # Patch: run quick=False but only IDOR — we use the engine with quick=True
    # then override by running idor_tester directly. For simplicity we use engine
    # with quick=False; non-IDOR results are discarded after the fact.
    engine = ScanEngine(cfg, verbose=False, quick=False)
    findings = asyncio.run(engine.run(ep_list))
    idor_findings = [f for f in findings if f.test_type == "idor"]
    console.print(f"[bold]IDOR Findings:[/bold] {len(idor_findings)}")
    sys.exit(0)


# ──────────────────────────────────────────────────────────────────────────────
# jwt command
# ──────────────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--config", "-c", required=True, help="Path to config.yaml")
@click.option("--token", "-t", required=True, help="JWT token to analyse and test")
def jwt(config: str, token: str) -> None:
    """Analyse a JWT token and generate test variants."""
    cfg = _load_config(config)

    parsed = parse_jwt(token)
    if not parsed:
        print_error("Provided string does not appear to be a valid JWT.")
        sys.exit(1)

    console.print("\n[bold]JWT Analysis[/bold]")
    console.print(f"  [dim]Algorithm:[/dim] {parsed['header'].get('alg', 'unknown')}")
    claims = parsed["payload"]
    for key, val in claims.items():
        console.print(f"  [dim]{key}:[/dim] {val}")

    console.print("\n[bold]Generated Test Tokens[/bold]")

    expired = make_expired_token(token)
    none_alg = make_none_alg_token(token)
    role_mod = make_role_modified_token(token, "admin")
    malformed = make_malformed_token()

    if expired:
        console.print(f"\n[yellow]Expired Token (alg:none, exp=-24h):[/yellow]")
        console.print(f"  [dim]{expired[:80]}...[/dim]")
    if none_alg:
        console.print(f"\n[yellow]alg:none Token (original payload):[/yellow]")
        console.print(f"  [dim]{none_alg[:80]}...[/dim]")
    if role_mod:
        console.print(f"\n[yellow]Role-Modified Token (role=admin, alg:none):[/yellow]")
        console.print(f"  [dim]{role_mod[:80]}...[/dim]")
    console.print(f"\n[yellow]Malformed Token:[/yellow]")
    console.print(f"  [dim]{malformed}[/dim]")
    console.print()
    console.print("[dim]Use these tokens manually to test endpoints. "
                  "AuthPulse tests them automatically during a full scan.[/dim]")


# ──────────────────────────────────────────────────────────────────────────────
# validate-config command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("validate-config")
@click.option("--config", "-c", required=True, help="Path to config.yaml to validate")
def validate_config(config: str) -> None:
    """Validate a config.yaml file without running a scan."""
    cfg = _load_config(config)
    errors: list[str] = []

    target = cfg.get("target", {})
    if not target.get("base_url"):
        errors.append("target.base_url is required")

    auth = cfg.get("auth", {})
    method = auth.get("method", "")
    if method not in ("bearer_jwt", "api_key", "cookie_session", "oauth2"):
        errors.append(f"auth.method must be one of: bearer_jwt, api_key, cookie_session, oauth2 (got: '{method}')")

    users = cfg.get("users", {})
    if "low_priv" not in users:
        errors.append("users.low_priv is required")
    if "high_priv" not in users:
        errors.append("users.high_priv is required")

    if errors:
        for err in errors:
            print_error(err)
        sys.exit(1)
    else:
        console.print("[green]✅ Config is valid.[/green]")


if __name__ == "__main__":
    main()
