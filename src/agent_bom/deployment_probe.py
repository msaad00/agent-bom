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


def resolve_server_card_url(base_url: str | None) -> str:
    """Return the public MCP server-card URL for a deployment origin."""

    raw = (base_url or DEFAULT_BASE_URL).strip()
    if not raw:
        raw = DEFAULT_BASE_URL

    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"invalid base URL: {base_url!r}")
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme for deployment probe: {parts.scheme!r}")

    return urlunsplit((parts.scheme, parts.netloc, "/.well-known/mcp/server-card.json", "", ""))


def _fetch_json(
    url: str,
    *,
    bearer_token: str | None,
    attempts: int,
    backoff_seconds: float,
    timeout: float,
) -> dict[str, Any]:
    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - URL resolvers enforce http/https only
                payload = json.loads(response.read())
            if not isinstance(payload, dict):
                raise ValueError("deployment response must be a JSON object")
            return payload
        except (ValueError, json.JSONDecodeError, OSError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt == attempts:
                break
            sleep_seconds = max(backoff_seconds, 0.0) * attempt
            if sleep_seconds:
                sys.stderr.write(f"Attempt {attempt}/{attempts} failed for {url}. Retrying in {sleep_seconds:.0f}s...\n")
                time.sleep(sleep_seconds)

    raise RuntimeError(f"unable to fetch deployment metadata from {url}: {last_error}")


def fetch_health(
    base_url: str | None,
    *,
    bearer_token: str | None = None,
    attempts: int = 1,
    backoff_seconds: float = 0.0,
    timeout: float = 15.0,
) -> tuple[str, dict[str, Any]]:
    """Fetch and parse the MCP health payload with retry support."""

    health_url = resolve_health_url(base_url)
    payload = _fetch_json(
        health_url,
        bearer_token=bearer_token,
        attempts=attempts,
        backoff_seconds=backoff_seconds,
        timeout=timeout,
    )
    return health_url, payload


def fetch_server_card(
    base_url: str | None,
    *,
    bearer_token: str | None = None,
    attempts: int = 1,
    backoff_seconds: float = 0.0,
    timeout: float = 15.0,
) -> tuple[str, dict[str, Any]]:
    """Fetch the public MCP server card with bounded retries."""

    server_card_url = resolve_server_card_url(base_url)
    payload = _fetch_json(
        server_card_url,
        bearer_token=bearer_token,
        attempts=attempts,
        backoff_seconds=backoff_seconds,
        timeout=timeout,
    )
    return server_card_url, payload


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


def validate_server_card_release(
    payload: dict[str, Any],
    *,
    expected_version: str,
    expected_tool_count: int,
) -> dict[str, Any]:
    """Require exact version, inventory, and usable schemas for a release."""

    server_info = payload.get("serverInfo")
    if not isinstance(server_info, dict) or server_info.get("version") != expected_version:
        deployed = server_info.get("version") if isinstance(server_info, dict) else None
        raise ValueError(f"server-card version mismatch: deployed={deployed!r} expected={expected_version!r}")

    tools = payload.get("tools")
    if not isinstance(tools, list) or len(tools) != expected_tool_count:
        actual = len(tools) if isinstance(tools, list) else None
        raise ValueError(f"server-card tool count mismatch: deployed={actual!r} expected={expected_tool_count}")

    names: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ValueError("server-card tool schema is missing a non-empty name")
        if not isinstance(tool.get("inputSchema"), dict):
            raise ValueError(f"server-card tool schema is missing inputSchema for {tool['name']!r}")
        names.append(tool["name"])
    if len(set(names)) != len(names):
        raise ValueError("server-card tool schema contains duplicate tool names")
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
    parser.add_argument(
        "--server-card",
        action="store_true",
        help="Probe the public MCP server card instead of /health.",
    )
    parser.add_argument("--expected-version", default=None, help="Exact release version required from the server card.")
    parser.add_argument("--expected-tool-count", type=int, default=None, help="Exact released MCP tool count required.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.resolve_only:
            sys.stdout.write(f"{resolve_health_url(args.base_url)}\n")
            return 0

        if args.server_card:
            if not args.expected_version or args.expected_tool_count is None:
                raise ValueError("--server-card requires --expected-version and --expected-tool-count")
            _, payload = fetch_server_card(
                args.base_url,
                bearer_token=args.bearer_token,
                attempts=args.attempts,
                backoff_seconds=args.backoff_seconds,
                timeout=args.timeout,
            )
            payload = validate_server_card_release(
                payload,
                expected_version=args.expected_version,
                expected_tool_count=args.expected_tool_count,
            )
        else:
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
