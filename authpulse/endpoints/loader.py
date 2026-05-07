"""Loads endpoint lists from JSON, plain text, and ParamSpider Pro formats."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".txt", ".xml",
    ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3", ".webp", ".avif",
}

# Regex to detect path parameters like {id}, :id, <id>, [id]
_PARAM_RE = re.compile(
    r"\{([^}]+)\}|:([A-Za-z_][A-Za-z0-9_]*)|<([^>]+)>|\[([^\]]+)\]"
)


@dataclass
class Endpoint:
    """A single API endpoint to test."""

    url: str          # relative path, e.g. /api/v1/users/{id}
    method: str       # HTTP method, uppercased
    params: list[str] = field(default_factory=list)  # detected path param names
    body_template: dict[str, Any] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        if not self.params:
            self.params = _extract_path_params(self.url)

    @property
    def has_id_param(self) -> bool:
        """Return True if the path contains a resource identifier parameter."""
        return bool(self.params) or bool(re.search(r"/\d+(/|$)", self.url))

    @property
    def is_static(self) -> bool:
        path = self.url.split("?")[0].lower()
        return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

    def normalised_url(self) -> str:
        """Return URL with path params replaced by placeholder {param}."""
        url = self.url
        # normalise :param → {param}
        url = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", url)
        # normalise <param> → {param}
        url = re.sub(r"<([^>]+)>", r"{\1}", url)
        # normalise [param] → {param}
        url = re.sub(r"\[([^\]]+)\]", r"{\1}", url)
        return url

    def concrete_url(self, replacements: dict[str, str]) -> str:
        """Return a URL with path params substituted with *replacements*."""
        url = self.normalised_url()
        for key, value in replacements.items():
            url = url.replace(f"{{{key}}}", value)
        return url


def _extract_path_params(url: str) -> list[str]:
    names: list[str] = []
    for match in _PARAM_RE.finditer(url):
        name = next(g for g in match.groups() if g is not None)
        names.append(name)
    return names


class EndpointLoader:
    """Loads and normalises endpoints from various input formats."""

    def __init__(self, skip_static: bool = True) -> None:
        self.skip_static = skip_static

    def load(self, source: str | Path) -> list[Endpoint]:
        """Auto-detect format and load endpoints from *source* (path or JSON string)."""
        path = Path(source) if not isinstance(source, Path) else source

        if path.exists():
            content = path.read_text(encoding="utf-8")
            suffix = path.suffix.lower()
            if suffix == ".json":
                return self._load_json(content)
            else:
                return self._load_text(content)

        # Treat as raw JSON string
        try:
            return self._load_json(str(source))
        except Exception:
            return self._load_text(str(source))

    def load_from_list(self, items: list[dict[str, Any]]) -> list[Endpoint]:
        """Load endpoints from an already-parsed list of dicts."""
        endpoints: list[Endpoint] = []
        for item in items:
            ep = self._dict_to_endpoint(item)
            if ep and self._should_include(ep):
                endpoints.append(ep)
        return endpoints

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _load_json(self, content: str) -> list[Endpoint]:
        data = json.loads(content)
        endpoints: list[Endpoint] = []

        # ParamSpider Pro / {"endpoints": [...]} format
        if isinstance(data, dict) and "endpoints" in data:
            raw_list = data["endpoints"]
        # Plain list of dicts
        elif isinstance(data, list):
            raw_list = data
        else:
            raise ValueError("Unrecognised JSON format")

        for item in raw_list:
            ep = self._dict_to_endpoint(item)
            if ep and self._should_include(ep):
                endpoints.append(ep)
        return endpoints

    def _load_text(self, content: str) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ep = self._line_to_endpoint(line)
            if ep and self._should_include(ep):
                endpoints.append(ep)
        return endpoints

    def _dict_to_endpoint(self, item: dict[str, Any]) -> Endpoint | None:
        url = item.get("url") or item.get("path") or item.get("endpoint")
        method = item.get("method", "GET")
        if not url:
            return None
        return Endpoint(
            url=str(url),
            method=str(method).upper(),
            body_template=item.get("body", {}),
            query_params=item.get("query_params", {}),
            headers=item.get("headers", {}),
            tags=item.get("tags", []),
        )

    def _line_to_endpoint(self, line: str) -> Endpoint | None:
        """Parse a line like 'GET /api/v1/users/123' or just '/api/v1/users'."""
        parts = line.split(None, 1)
        if len(parts) == 2:
            method, url = parts[0].upper(), parts[1]
            if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                return Endpoint(url=url, method=method)
        # If single token, assume GET
        url = parts[0]
        return Endpoint(url=url, method="GET")

    def _should_include(self, ep: Endpoint) -> bool:
        if self.skip_static and ep.is_static:
            return False
        return True
