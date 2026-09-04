#!/usr/bin/env python3
"""Cross-channel version-freshness monitor for every published agent-bom surface.

Compares the repo's expected version (pyproject.toml) against each distribution
surface and emits a single consolidated JSON report. A scheduled workflow turns
that report into ONE tracking issue so a stale surface can never silently sit
unnoticed for months (root cause of the 3-month Smithery drift).

Surfaces probed:
    pypi      — https://pypi.org/pypi/agent-bom/json  -> info.version
    docker    — ghcr.io / Docker Hub latest tag       -> resolved via registry API
    glama     — public marketplace listing            -> scripts/check_glama_listing.py
    smithery  — public Smithery catalog API            -> api.smithery.ai

Each surface reports one of:
    fresh          — published version == expected
    stale          — published version != expected
    not_configured — required URL/var missing (treated as a MISCONFIGURATION, not skipped)
    unreachable    — configured but probe failed

The script always exits 0 — the workflow inspects the JSON and decides whether to
open/refresh/close the tracking issue. This keeps the scheduled run itself green
while still surfacing drift through the issue tracker.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
GLAMA_SCRIPT = ROOT / "scripts" / "check_glama_listing.py"

PYPI_PACKAGE = "agent-bom"
DEFAULT_DOCKER_IMAGE = "ghcr.io/msaad00/agent-bom"
DEFAULT_SMITHERY_SERVER = "agent-bom/agent-bom"
# Requests to this origin carry an anonymous-pull bearer token, so pagination
# links must never move off it.
GHCR_ORIGIN = "https://ghcr.io"
DEFAULT_TIMEOUT = 15.0
DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF = 5.0

OK_STATUSES = {"fresh"}


def expected_tool_count() -> int:
    """Return the shipped MCP tool inventory size, from the one place it lives.

    ``check_glama_listing.py`` already derives this from the README contract
    sentence. Re-deriving it here would be a second answer to one question, and
    the two would eventually disagree — so this delegates to that module rather
    than re-reading the README.
    """
    spec = importlib.util.spec_from_file_location("_glama_listing_contract", GLAMA_SCRIPT)
    if spec is None or spec.loader is None:  # pragma: no cover - packaging accident
        raise SystemExit(f"could not load {GLAMA_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return int(module._load_readme_tool_count())


def _load_expected_tool_names(path: Path) -> list[str]:
    """Load a release-bound tool-name contract from a JSON list."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read expected tool-name contract: {exc}") from exc
    if not isinstance(payload, list) or not payload or not all(isinstance(name, str) and name for name in payload):
        raise SystemExit("expected tool-name contract must be a non-empty JSON string list")
    if len(payload) != len(set(payload)):
        raise SystemExit("expected tool-name contract contains duplicate names")
    return sorted(payload)


def _env_or(name: str, default: str) -> str:
    """Return env var if non-blank; otherwise ``default``.

    GitHub Actions injects unset ``vars.*`` as empty strings into ``env:``, so
    ``os.environ.get(name, default)`` would keep ``""`` and skip the default.
    """
    value = (os.environ.get(name) or "").strip()
    return value or default


def _expected_version() -> str:
    text = PYPROJECT.read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise SystemExit("could not read version from pyproject.toml")
    return m.group(1)


def _http_json_response(
    url: str,
    *,
    timeout: float,
    attempts: int,
    backoff: float,
    headers: dict[str, str] | None = None,
) -> tuple[Any, Any]:
    last = "unknown error"
    hdrs = {"Accept": "application/json", "User-Agent": "agent-bom-freshness-probe"}
    if headers:
        hdrs.update(headers)
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace")), resp.headers
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            last = f"network error: {exc}"
        except json.JSONDecodeError as exc:
            last = f"invalid JSON: {exc}"
        if attempt < attempts:
            time.sleep(backoff * attempt)
    raise RuntimeError(last)


def _http_json(url: str, *, timeout: float, attempts: int, backoff: float, headers: dict[str, str] | None = None) -> Any:
    data, _headers = _http_json_response(url, timeout=timeout, attempts=attempts, backoff=backoff, headers=headers)
    return data


def _classify(name: str, published: str | None, expected: str, *, error: str | None = None) -> dict[str, Any]:
    if error:
        return {"surface": name, "status": "unreachable", "version": published or "—", "expected": expected, "error": error}
    if not published:
        return {"surface": name, "status": "unreachable", "version": "—", "expected": expected, "error": "no version found"}
    status = "fresh" if published == expected else "stale"
    return {"surface": name, "status": status, "version": published, "expected": expected}


def _smithery_catalog_url(qualified_name: str) -> str:
    """Return the public Smithery catalog API URL for ``namespace/server``."""

    name = qualified_name.strip()
    if "/" not in name:
        raise ValueError(f"invalid Smithery qualified name: {qualified_name!r}")
    namespace, server = name.split("/", 1)
    if not namespace or not server or "/" in server:
        raise ValueError(f"invalid Smithery qualified name: {qualified_name!r}")
    return f"https://api.smithery.ai/servers/{urllib.parse.quote(namespace, safe='')}/{urllib.parse.quote(server, safe='')}"


def _parse_image_reference(image: str) -> tuple[str, str]:
    """Return (registry, repository) for supported container image references."""
    raw = image.strip()
    if not raw:
        raise ValueError("empty image reference")
    if "://" in raw:
        raise ValueError("image reference must not be a URL")
    without_digest = raw.split("@", 1)[0]
    parts = without_digest.split("/")
    if ":" in parts[-1]:
        parts[-1] = parts[-1].split(":", 1)[0]

    first = parts[0].lower()
    has_registry = len(parts) > 1 and ("." in first or ":" in first or first == "localhost")
    registry = first if has_registry else "docker.io"
    repo_parts = parts[1:] if has_registry else parts
    if registry in {"docker.io", "index.docker.io"} and len(repo_parts) == 1:
        repo_parts = ["library", repo_parts[0]]

    repo = "/".join(p.strip() for p in repo_parts if p.strip())
    if not repo or not re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+", repo):
        raise ValueError(f"unsupported image repository: {image!r}")
    return registry, repo


def probe_pypi(expected: str, **kw: Any) -> dict[str, Any]:
    try:
        data = _http_json("https://pypi.org/pypi/agent-bom/json", **kw)
        version = (data.get("info") or {}).get("version")
        return _classify("PyPI", version, expected)
    except RuntimeError as exc:
        return _classify("PyPI", None, expected, error=str(exc))


def _require_origin(url: str, origin: str) -> str:
    """Return ``url`` only if it stays on ``origin``.

    Anything we follow while holding a token has to be pinned to the origin that
    issued it. ``scripts/dockerhub_tag_cleanup.py`` makes the same check for
    Docker Hub; this is the second caller, not a second rule.
    """
    parts = urllib.parse.urlsplit(url)
    if f"{parts.scheme}://{parts.netloc}" != origin:
        raise RuntimeError(f"refusing to follow off-origin pagination URL: {url!r}")
    return url


def probe_docker(expected: str, image: str, **kw: Any) -> dict[str, Any]:
    """Confirm the expected tag exists on the registry.

    For ghcr we query the package-tags listing (anonymous for public packages);
    for Docker Hub we query the registry tags API. Presence of the exact version
    tag means the release was published; absence means it is missing/stale.
    """
    image = image.strip()
    try:
        registry, repo = _parse_image_reference(image)
        if registry == "ghcr.io":
            # ghcr public images: token from anonymous auth, then registry tags list.
            scope_repo = urllib.parse.quote(repo, safe="")
            path_repo = urllib.parse.quote(repo, safe="/")
            token_data = _http_json(
                f"https://ghcr.io/token?scope=repository:{scope_repo}:pull&service=ghcr.io",
                **kw,
            )
            token = token_data.get("token", "")
            tags: set[str] = set()
            next_url = f"https://ghcr.io/v2/{path_repo}/tags/list?n=100"
            auth_headers = {"Authorization": f"Bearer {token}"} if token else None
            for _page in range(20):
                tags_data, response_headers = _http_json_response(next_url, headers=auth_headers, **kw)
                tags.update(tags_data.get("tags") or [])
                link = response_headers.get("Link", "")
                match = re.search(r'<([^>]+)>;\s*rel="next"', link)
                if not match:
                    break
                # urljoin returns an absolute URL unchanged, so a registry-supplied
                # ``Link: <https://elsewhere/…>`` would move the host while the
                # bearer token stayed attached. Every page of this walk is
                # authenticated, so every page must stay on the registry.
                next_url = _require_origin(urllib.parse.urljoin(GHCR_ORIGIN, match.group(1)), GHCR_ORIGIN)
        else:
            tags = set()
            url = f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100"
            data = _http_json(url, **kw)
            for entry in data.get("results", []):
                if entry.get("name"):
                    tags.add(entry["name"])
        # Registries publish either bare (0.88.6) or v-prefixed (v0.88.6) tags;
        # normalize so the comparison is prefix-insensitive.
        norm = {t.lstrip("v") for t in tags}
        if expected in norm:
            return _classify("Docker", expected, expected)
        # The expected tag is missing — report the surface as stale, naming the
        # newest semver tag we did find so the issue is actionable.
        semver = sorted(
            (t for t in norm if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", t)),
            key=lambda v: [int(p) for p in v.split(".")],
        )
        return _classify("Docker", semver[-1] if semver else None, expected)
    except RuntimeError as exc:
        return _classify("Docker", None, expected, error=str(exc))
    except ValueError as exc:
        return _classify("Docker", None, expected, error=str(exc))


def probe_glama(
    expected: str,
    *,
    expected_tool_count: int | None = None,
    expected_tool_names_file: Path | None = None,
    **kw: Any,
) -> dict[str, Any]:
    """Delegate to check_glama_listing.py so the probe logic stays in one place."""
    command = [sys.executable, str(GLAMA_SCRIPT), "--expected", expected, "--json"]
    if expected_tool_count is not None:
        command.extend(["--expected-tool-count", str(expected_tool_count)])
    if expected_tool_names_file is not None:
        command.extend(["--expected-tool-names-file", str(expected_tool_names_file)])
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    raw = (proc.stdout or "").strip().splitlines()
    payload: dict[str, Any] = {}
    for line in reversed(raw):
        try:
            payload = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    status = payload.get("status", "unreachable")
    return {
        "surface": "Glama",
        "status": status,
        "version": payload.get("listing_version", "—"),
        "expected": expected,
        "tool_count": payload.get("tool_count"),
        "expected_tool_count": payload.get("expected_tool_count"),
        "exact_tool_set": payload.get("exact_tool_set"),
        "exact_input_schemas": payload.get("exact_input_schemas"),
        "degraded_reason": payload.get("degraded_reason"),
        "error": payload.get("error"),
    }


def probe_smithery(
    expected: str,
    qualified_name: str,
    *,
    expected_tool_count: int | None = None,
    expected_tool_names: list[str] | None = None,
    **kw: Any,
) -> dict[str, Any]:
    """Probe Smithery's public catalog listing.

    Smithery-hosted remote servers are OAuth-gated and do not expose agent-bom's
    raw `/health` route. Freshness for this surface is therefore the catalog
    contract: the listing exists, is remote, has a deployment URL, and advertises
    the full shipped tool inventory. Version freshness is covered by PyPI/Docker
    plus the protected Railway health check.

    The tool count is part of that contract. A listing that advertises a strict
    subset is a stale snapshot, and asserting only that the list is non-empty
    cannot tell the two apart — which is how a partial listing sat unnoticed.
    """

    try:
        data = _http_json(_smithery_catalog_url(qualified_name), **kw)
        tools = data.get("tools") if isinstance(data.get("tools"), list) else []
        deployment_url = data.get("deploymentUrl")
        if data.get("qualifiedName") != qualified_name:
            return _classify("Smithery", "—", expected, error="catalog returned the wrong server")
        if not data.get("remote"):
            return _classify("Smithery", "—", expected, error="catalog listing is not marked remote")
        if not deployment_url:
            return _classify("Smithery", "—", expected, error="catalog listing has no deploymentUrl")
        if not tools:
            return _classify("Smithery", "—", expected, error="catalog listing has no tools")
        result = {
            "surface": "Smithery",
            "status": "fresh",
            "version": "catalog-live",
            "expected": expected,
            "deployment_url": deployment_url,
            "tool_count": len(tools),
        }
        actual_tool_names = sorted(
            tool.get("name") for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        )
        if expected_tool_count is not None:
            result["expected_tool_count"] = expected_tool_count
            if len(tools) != expected_tool_count:
                result["status"] = "stale"
                result["error"] = f"catalog advertises {len(tools)} tools; expected {expected_tool_count}"
        if expected_tool_names is not None:
            exact_tool_set = actual_tool_names == expected_tool_names
            result["exact_tool_set"] = exact_tool_set
            if not exact_tool_set:
                result["status"] = "stale"
                missing = sorted(set(expected_tool_names) - set(actual_tool_names))
                unexpected = sorted(set(actual_tool_names) - set(expected_tool_names))
                result["error"] = (
                    "catalog tool-name set differs from the immutable release contract"
                    f"; missing={missing or 'none'}; unexpected={unexpected or 'none'}"
                )
        return result
    except (RuntimeError, ValueError) as exc:
        return _classify("Smithery", None, expected, error=str(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", default=None, help="Override expected version (defaults to pyproject.toml).")
    # One shipped tool inventory, so one expectation. The Glama-specific spelling
    # stays accepted because the workflow passes it.
    parser.add_argument("--expected-tool-count", "--expected-glama-tool-count", dest="expected_tool_count", type=int, default=None)
    parser.add_argument(
        "--expected-tool-names-file",
        type=Path,
        default=None,
        help="JSON list of immutable released MCP tool names required from marketplace inventories.",
    )
    parser.add_argument("--docker-image", default=_env_or("DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE))
    parser.add_argument("--smithery-server", default=_env_or("SMITHERY_SERVER_QUALIFIED_NAME", DEFAULT_SMITHERY_SERVER))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--backoff-seconds", type=float, default=DEFAULT_BACKOFF)
    parser.add_argument("--out", default=None, help="Write the consolidated JSON report to this path.")
    parser.add_argument(
        "--fail-on-stale",
        action="store_true",
        help=(
            "Exit non-zero when any surface has drifted. Without it this script always "
            "exits 0, so a stale surface is reported and no gate can act on it — which "
            "is how Smithery sat at 36 of 77 tools through a release."
        ),
    )
    args = parser.parse_args(argv)

    expected = (args.expected or _expected_version()).lstrip("v").strip()
    # Default it rather than leaving it None. An unset expectation used to turn
    # the tool-count assertion off for Smithery entirely, so a bare local run
    # reported a catalog advertising 36 of 77 tools as fresh — the drift this
    # monitor exists to catch, invisible to the person most likely to look.
    tool_count = args.expected_tool_count if args.expected_tool_count is not None else expected_tool_count()
    expected_tool_names = _load_expected_tool_names(args.expected_tool_names_file) if args.expected_tool_names_file else None
    if expected_tool_names is not None and len(expected_tool_names) != tool_count:
        raise SystemExit("expected tool-name contract and tool count do not match")
    kw = {"timeout": args.timeout, "attempts": args.attempts, "backoff": args.backoff_seconds}

    surfaces = [
        probe_pypi(expected, **kw),
        probe_docker(expected, args.docker_image, **kw),
        probe_glama(
            expected,
            expected_tool_count=tool_count,
            expected_tool_names_file=args.expected_tool_names_file,
            **kw,
        ),
        probe_smithery(
            expected,
            args.smithery_server,
            expected_tool_count=tool_count,
            expected_tool_names=expected_tool_names,
            **kw,
        ),
    ]

    drift = [s for s in surfaces if s["status"] not in OK_STATUSES]
    report = {
        "expected": expected,
        "all_fresh": len(drift) == 0,
        "surfaces": surfaces,
    }

    out = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n")
    print(out)
    if drift and args.fail_on_stale:
        names = ", ".join(f"{s['surface']} ({s['status']})" for s in drift)
        print(f"\nSurface drift: {names}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
