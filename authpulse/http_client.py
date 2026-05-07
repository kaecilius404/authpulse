"""Async-compatible HTTP request helper.

Uses aiohttp when available; falls back to urllib via run_in_executor.
All callers use `await fetch(...)` regardless of backend.
"""

from __future__ import annotations

import asyncio
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from authpulse.models import ResponseSnapshot

# Try aiohttp
try:
    import aiohttp as _aiohttp
    _AIOHTTP = True
except ImportError:
    _aiohttp = None  # type: ignore
    _AIOHTTP = False


def _make_ssl_ctx(verify: bool) -> ssl.SSLContext | bool:
    if verify:
        return ssl.create_default_context()
    ctx = ssl._create_unverified_context()
    return ctx


def _sync_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None,
    params: dict[str, str] | None,
    verify_ssl: bool,
    timeout: float,
) -> ResponseSnapshot:
    """Synchronous HTTP request via urllib."""
    if params:
        url = url + "?" + urllib.parse.urlencode(params)

    data: bytes | None = None
    req_headers = dict(headers)
    if body is not None:
        data = json.dumps(body).encode()
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
    ctx = _make_ssl_ctx(verify_ssl)

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            raw = resp.read()
            try:
                body_text = raw.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            resp_headers = dict(resp.headers)
            return ResponseSnapshot.from_response_data(resp.status, body_text, resp_headers)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
            body_text = raw.decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        return ResponseSnapshot.from_response_data(exc.code, body_text, {})
    except Exception:
        return ResponseSnapshot.from_response_data(0, "", {})


async def fetch(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    verify_ssl: bool,
    body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> ResponseSnapshot:
    """Async HTTP fetch.  Uses aiohttp if available, otherwise urllib."""
    if _AIOHTTP:
        return await _aiohttp_fetch(method, url, headers, cookies, verify_ssl, body, params, timeout)
    # urllib fallback — run in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    merged_headers = dict(headers)
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        merged_headers["Cookie"] = cookie_str
    return await loop.run_in_executor(
        None,
        _sync_request,
        method, url, merged_headers, body, params, verify_ssl, timeout,
    )


async def _aiohttp_fetch(
    method: str,
    url: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    verify_ssl: bool,
    body: dict[str, Any] | None,
    params: dict[str, str] | None,
    timeout: float,
) -> ResponseSnapshot:
    ssl_ctx: Any = None if verify_ssl else False
    try:
        connector = _aiohttp.TCPConnector(ssl=ssl_ctx)
        async with _aiohttp.ClientSession(connector=connector) as session:
            async with session.request(
                method, url, headers=headers, cookies=cookies,
                json=body, params=params,
                timeout=_aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                try:
                    body_text = await resp.text(errors="replace")
                except Exception:
                    body_text = ""
                return ResponseSnapshot.from_response_data(
                    resp.status, body_text, dict(resp.headers)
                )
    except Exception:
        return ResponseSnapshot.from_response_data(0, "", {})
