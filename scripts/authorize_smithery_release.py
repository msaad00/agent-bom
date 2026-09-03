#!/usr/bin/env python3
"""Complete a Smithery scan authorization against the trusted MCP origin.

Smithery pauses authenticated external-server scans and records the OAuth
authorization URL in the release log. Agent-Bom's broker authorization endpoint
is deliberately machine-to-machine: a valid registered PKCE client is granted
and redirected immediately. This helper follows that one bounded flow without
printing the URL, whose query contains ephemeral OAuth state.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

_AUTH_PATH = "/oauth/authorize"
_SMITHERY_CALLBACK_HOST = "server.smithery.ai"
_SMITHERY_CALLBACK_PATH = "/oauth/callback"
_MAX_RELEASE_BYTES = 2 * 1024 * 1024
_URL_RE = re.compile(r"https?://[^\s<>\"']+")


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _origin(parts: Any) -> tuple[str, str, int | None]:
    scheme = parts.scheme.lower()
    port = parts.port
    if port is None and scheme == "https":
        port = 443
    return scheme, (parts.hostname or "").lower(), port


def _endpoint(parts: Any) -> tuple[str, str, int | None, str]:
    return (*_origin(parts), parts.path)


def _authorization_callback_url(authorization_url: str) -> str:
    authorization = urlsplit(authorization_url)
    if (
        authorization.scheme.lower() != "https"
        or not authorization.hostname
        or authorization.username
        or authorization.password
        or authorization.path != _AUTH_PATH
    ):
        raise ValueError("authorization URL must use the trusted HTTPS endpoint")

    redirect_values = parse_qs(authorization.query, keep_blank_values=True).get("redirect_uri", [])
    if len(redirect_values) != 1:
        raise ValueError("authorization URL must contain one Smithery redirect_uri")
    callback = urlsplit(redirect_values[0])
    if (
        callback.scheme.lower() != "https"
        or not callback.hostname
        or callback.hostname.lower().rstrip(".") != _SMITHERY_CALLBACK_HOST
        or _origin(callback)[2] != 443
        or callback.path != _SMITHERY_CALLBACK_PATH
        or callback.username
        or callback.password
        or callback.query
        or callback.fragment
    ):
        raise ValueError("Smithery redirect_uri must use a trusted HTTPS origin")
    return redirect_values[0]


def extract_authorization_url(release: Any, upstream_url: str) -> str | None:
    """Return the first exact-origin Agent-Bom authorization URL in release logs."""
    upstream = urlsplit(upstream_url)
    if upstream.scheme.lower() != "https" or not upstream.hostname:
        raise ValueError("Smithery upstream must be an HTTPS URL")

    for text in _strings(release):
        for raw in _URL_RE.findall(text):
            candidate = raw.rstrip(".,;:)]}")
            parsed = urlsplit(candidate)
            if _origin(parsed) == _origin(upstream) and parsed.path == _AUTH_PATH and parsed.query:
                return candidate
    return None


class _BoundedRedirectHandler(HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def __init__(self, *, authorization_url: str, callback_url: str) -> None:
        super().__init__()
        self._authorization_endpoint = _endpoint(urlsplit(authorization_url))
        self._callback_endpoint = _endpoint(urlsplit(callback_url))
        self.allowed_origins = {
            _origin(urlsplit(authorization_url)),
            _origin(urlsplit(callback_url)),
        }

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        destination = urlsplit(newurl)
        if (
            _endpoint(urlsplit(req.full_url)) != self._authorization_endpoint
            or destination.scheme.lower() != "https"
            or destination.username
            or destination.password
            or _endpoint(destination) != self._callback_endpoint
        ):
            raise ValueError("authorization redirect must use one exact callback on a trusted HTTPS origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_opener(request: Request, *, timeout: float, redirect_handler: _BoundedRedirectHandler):
    return build_opener(redirect_handler).open(request, timeout=timeout)


def complete_authorization(
    authorization_url: str,
    *,
    opener: Callable[..., Any] = _default_opener,
) -> None:
    """Follow the registered PKCE authorization callback with strict bounds."""
    callback_url = _authorization_callback_url(authorization_url)
    redirect_handler = _BoundedRedirectHandler(authorization_url=authorization_url, callback_url=callback_url)
    request = Request(
        authorization_url,
        headers={"User-Agent": "agent-bom-registry-reconciler/1"},
        method="GET",
    )
    with opener(request, timeout=30.0, redirect_handler=redirect_handler) as response:
        status = int(getattr(response, "status", 200))
        response.read(4096)
        final_url = response.geturl()
    if status >= 400 or _endpoint(urlsplit(final_url)) != _endpoint(urlsplit(callback_url)):
        raise RuntimeError("Smithery scan authorization callback failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--upstream-url", required=True)
    args = parser.parse_args(argv)

    try:
        if args.release_json.stat().st_size > _MAX_RELEASE_BYTES:
            raise ValueError("release response exceeds the bounded input size")
        release = json.loads(args.release_json.read_text(encoding="utf-8"))
        authorization_url = extract_authorization_url(release, args.upstream_url)
        if authorization_url is None:
            print("Smithery release did not expose a trusted Agent-Bom authorization URL", file=sys.stderr)
            return 2
        complete_authorization(authorization_url)
    except Exception:  # noqa: BLE001 - OAuth state and provider responses must not reach CI logs
        print("Smithery scan authorization could not be completed safely", file=sys.stderr)
        return 1

    print("Smithery scan authorization callback completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
