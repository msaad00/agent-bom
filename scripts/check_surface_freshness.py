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
    smithery  — public MCP endpoint                    -> agent_bom.deployment_probe

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
DEFAULT_TIMEOUT = 15.0
DEFAULT_ATTEMPTS = 3
DEFAULT_BACKOFF = 5.0

OK_STATUSES = {"fresh"}
ALERT_STATUSES = {"stale", "not_configured", "unreachable"}


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


def _smithery_proxy_error(url: str) -> str | None:
    """Return an actionable error when the configured URL is Smithery's proxy."""

    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.netloc.lower() == "server.smithery.ai":
        return (
            "SMITHERY_MCP_URL points at Smithery's hosted MCP proxy. Set it to "
            "the upstream public unauthenticated endpoint that exposes /health, "
            "not https://server.smithery.ai/.../mcp."
        )
    return None


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
            tags = set()
            next_url = f"https://ghcr.io/v2/{path_repo}/tags/list?n=100"
            auth_headers = {"Authorization": f"Bearer {token}"} if token else None
            for _page in range(20):
                tags_data, response_headers = _http_json_response(next_url, headers=auth_headers, **kw)
                tags.update(tags_data.get("tags") or [])
                link = response_headers.get("Link", "")
                match = re.search(r'<([^>]+)>;\s*rel="next"', link)
                if not match:
                    break
                next_url = urllib.parse.urljoin("https://ghcr.io", match.group(1))
        else:
            tags: set[str] = set()
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


def probe_glama(expected: str, **kw: Any) -> dict[str, Any]:
    """Delegate to check_glama_listing.py so the probe logic stays in one place."""
    proc = subprocess.run(
        [sys.executable, str(GLAMA_SCRIPT), "--expected", expected, "--json"],
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
        "error": payload.get("error"),
    }


def probe_smithery(expected: str, url: str, **kw: Any) -> dict[str, Any]:
    if not url:
        return {
            "surface": "Smithery",
            "status": "not_configured",
            "version": "—",
            "expected": expected,
            "error": "no SMITHERY_MCP_URL — set the repo variable to monitor this surface",
        }
    proxy_error = _smithery_proxy_error(url)
    if proxy_error:
        return {
            "surface": "Smithery",
            "status": "not_configured",
            "version": "—",
            "expected": expected,
            "error": proxy_error,
        }
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_bom.deployment_probe",
                "--base-url",
                url,
                "--attempts",
                str(kw.get("attempts", DEFAULT_ATTEMPTS)),
                "--backoff-seconds",
                str(kw.get("backoff", DEFAULT_BACKOFF)),
                "--timeout",
                str(kw.get("timeout", DEFAULT_TIMEOUT)),
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )
        if proc.returncode != 0:
            error = (proc.stderr or proc.stdout or f"deployment_probe exited {proc.returncode}").strip()
            return _classify("Smithery", None, expected, error=error)
        data = json.loads(proc.stdout or "{}")
        version = data.get("version")
        return _classify("Smithery", version, expected)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        return _classify("Smithery", None, expected, error=str(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", default=None, help="Override expected version (defaults to pyproject.toml).")
    parser.add_argument("--docker-image", default=os.environ.get("DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE))
    parser.add_argument("--smithery-url", default=os.environ.get("SMITHERY_MCP_URL", ""))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--backoff-seconds", type=float, default=DEFAULT_BACKOFF)
    parser.add_argument("--out", default=None, help="Write the consolidated JSON report to this path.")
    args = parser.parse_args(argv)

    expected = (args.expected or _expected_version()).lstrip("v").strip()
    kw = {"timeout": args.timeout, "attempts": args.attempts, "backoff": args.backoff_seconds}

    surfaces = [
        probe_pypi(expected, **kw),
        probe_docker(expected, args.docker_image, **kw),
        probe_glama(expected, **kw),
        probe_smithery(expected, args.smithery_url, **kw),
    ]

    drift = [s for s in surfaces if s["status"] in ALERT_STATUSES]
    report = {
        "expected": expected,
        "all_fresh": len(drift) == 0,
        "surfaces": surfaces,
    }

    out = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
