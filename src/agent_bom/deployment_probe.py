"""Helpers for Railway/MCP deployment health probes used in CI workflows."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit, urlunsplit

DEFAULT_BASE_URL = "https://agent-bom-mcp.up.railway.app"
_USER_AGENT = "agent-bom-deployment-probe"


def resolve_health_url(base_url: str | None) -> str:
    """Return the canonical MCP health URL for a base Railway endpoint.

    ``RAILWAY_MCP_URL`` is used in two different shapes across the repo:
    the bare Railway host for health probes and the ``/mcp`` endpoint for
    registry publishing. CI should accept either form and normalize both to
    the real health route exposed by the MCP server.
    """

    raw = (base_url or DEFAULT_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_BASE_URL

    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"invalid base URL: {base_url!r}")
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme for deployment probe: {parts.scheme!r}")

    path = parts.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[: -len("/mcp")]

    path = f"{path}/health" if path else "/health"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def fetch_health(
    base_url: str | None,
    *,
    bearer_token: str | None = None,
    attempts: int = 1,
    backoff_seconds: float = 0.0,
    timeout: float = 15.0,
) -> tuple[str, dict[str, Any]]:
    """Fetch and parse the MCP health payload with retry support."""

    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    health_url = resolve_health_url(base_url)
    headers = {"User-Agent": _USER_AGENT}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(health_url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - resolve_health_url enforces http/https only
                payload = json.loads(response.read())
            if not isinstance(payload, dict):
                raise ValueError("health response must be a JSON object")
            return health_url, payload
        except (ValueError, json.JSONDecodeError, OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            sleep_seconds = max(backoff_seconds, 0.0) * attempt
            if sleep_seconds:
                sys.stderr.write(f"Attempt {attempt}/{attempts} failed for {health_url}: {exc}. Retrying in {sleep_seconds:.0f}s...\n")
                time.sleep(sleep_seconds)

    raise RuntimeError(f"unable to fetch MCP health from {health_url}: {last_error}")


def validate_health_payload(
    payload: dict[str, Any],
    *,
    forbid_auth_required: bool = False,
) -> dict[str, Any]:
    """Validate parsed health payload contract for deployment checks."""

    if not isinstance(payload, dict):
        raise ValueError("health response must be a JSON object")
    if forbid_auth_required and bool(payload.get("auth_required")):
        raise ValueError("deployment surface requires auth and is not suitable for public registry publishing")
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Probe the MCP health endpoint used by CI workflows.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Railway base URL or MCP endpoint URL.")
    parser.add_argument("--bearer-token", default=None, help="Optional bearer token for authenticated probes.")
    parser.add_argument("--attempts", type=int, default=1, help="Number of probe attempts before failing.")
    parser.add_argument(
        "--backoff-seconds",
        type=float,
        default=0.0,
        help="Linear backoff between attempts. Attempt N sleeps N * backoff seconds.",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--resolve-only",
        action="store_true",
        help="Print the normalized health URL without making a network request.",
    )
    parser.add_argument(
        "--forbid-auth-required",
        action="store_true",
        help="Fail if the health payload reports auth_required=true.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.resolve_only:
            sys.stdout.write(f"{resolve_health_url(args.base_url)}\n")
            return 0

        _, payload = fetch_health(
            args.base_url,
            bearer_token=args.bearer_token,
            attempts=args.attempts,
            backoff_seconds=args.backoff_seconds,
            timeout=args.timeout,
        )
        payload = validate_health_payload(
            payload,
            forbid_auth_required=args.forbid_auth_required,
        )
    except (RuntimeError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 1

    json.dump(payload, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
