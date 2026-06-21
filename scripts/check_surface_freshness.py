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


def _http_json(url: str, *, timeout: float, attempts: int, backoff: float, headers: dict[str, str] | None = None) -> Any:
    last = "unknown error"
    hdrs = {"Accept": "application/json", "User-Agent": "agent-bom-freshness-probe"}
    if headers:
        hdrs.update(headers)
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:  # noqa: PERF203
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            last = f"network error: {exc}"
        except json.JSONDecodeError as exc:
            last = f"invalid JSON: {exc}"
        if attempt < attempts:
            time.sleep(backoff * attempt)
    raise RuntimeError(last)


def _classify(name: str, published: str | None, expected: str, *, error: str | None = None) -> dict[str, Any]:
    if error:
        return {"surface": name, "status": "unreachable", "version": published or "—", "expected": expected, "error": error}
    if not published:
        return {"surface": name, "status": "unreachable", "version": "—", "expected": expected, "error": "no version found"}
    status = "fresh" if published == expected else "stale"
    return {"surface": name, "status": status, "version": published, "expected": expected}


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
        if image.startswith("ghcr.io/"):
            # ghcr public images: token from anonymous auth, then registry tags list.
            repo = image[len("ghcr.io/") :]
            token_data = _http_json(
                f"https://ghcr.io/token?scope=repository:{repo}:pull&service=ghcr.io",
                **kw,
            )
            token = token_data.get("token", "")
            tags_data = _http_json(
                f"https://ghcr.io/v2/{repo}/tags/list",
                headers={"Authorization": f"Bearer {token}"} if token else None,
                **kw,
            )
            tags = set(tags_data.get("tags") or [])
        else:
            repo = image if "/" in image else f"library/{image}"
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


def probe_glama(expected: str, **kw: Any) -> dict[str, Any]:
    """Delegate to check_glama_listing.py so the probe logic stays in one place."""
    proc = subprocess.run(  # noqa: S603
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
    try:
        proc = subprocess.run(  # noqa: S603
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
