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
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

_AUTH_PATH = "/oauth/authorize"
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
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port


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


def _default_opener(request: Request, *, timeout: float):
    return build_opener(_BoundedRedirectHandler()).open(request, timeout=timeout)


def complete_authorization(
    authorization_url: str,
    *,
    opener: Callable[..., Any] = _default_opener,
) -> None:
    """Follow the registered PKCE authorization callback with strict bounds."""
    request = Request(
        authorization_url,
        headers={"User-Agent": "agent-bom-registry-reconciler/1"},
        method="GET",
    )
    with opener(request, timeout=30.0) as response:
        status = int(getattr(response, "status", 200))
        response.read(4096)
    if status >= 400:
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
