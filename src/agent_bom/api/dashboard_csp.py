"""Dashboard Content-Security-Policy helpers.

The packaged dashboard is a static Next.js export. App Router builds include
inline bootstrap scripts, so release packaging generates hashes for those exact
inline blocks and the API can serve dashboard HTML without script-src
``'unsafe-inline'`` when the manifest is present.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_FALLBACK_REASON = "Next static export hash manifest is missing; dashboard falls back to inline script bootstrap compatibility."


def _manifest_path() -> Path:
    configured = os.environ.get("AGENT_BOM_DASHBOARD_CSP_HASH_MANIFEST", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[1] / "ui_dist" / "csp-hashes.json"


def _load_manifest() -> dict[str, list[str]]:
    path = _manifest_path()
    if not path.is_file():
        return {"script_hashes": [], "style_hashes": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"script_hashes": [], "style_hashes": []}
    return {
        "script_hashes": [str(value) for value in raw.get("script_hashes", []) if str(value).startswith("sha256-")],
        "style_hashes": [str(value) for value in raw.get("style_hashes", []) if str(value).startswith("sha256-")],
    }


def _csp_hash_source(value: str) -> str:
    normalized = value.strip().strip("'\"")
    return f"'{normalized}'"


def dashboard_csp_header() -> str:
    """Return the dashboard CSP header for the active packaged UI assets."""

    manifest = _load_manifest()
    script_hashes = manifest["script_hashes"]
    style_hashes = manifest["style_hashes"]
    script_src = " ".join(["'self'", *(_csp_hash_source(value) for value in script_hashes)]) if script_hashes else "'self' 'unsafe-inline'"
    # Next/font and Tailwind still emit inline style attributes in some builds.
    # Keep style inline compatibility until the dashboard removes those attrs.
    style_src_values = ["'self'", "'unsafe-inline'", *(_csp_hash_source(value) for value in style_hashes)]
    style_src = " ".join(dict.fromkeys(style_src_values))
    return (
        "default-src 'self'; "
        f"script-src {script_src}; "
        "script-src-attr 'none'; "
        f"style-src {style_src}; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )


def describe_dashboard_csp_posture() -> dict[str, Any]:
    """Return non-secret dashboard CSP posture for operator policy surfaces."""

    manifest = _load_manifest()
    script_hashes = manifest["script_hashes"]
    header = dashboard_csp_header()
    return {
        "header": header,
        "mode": "hash_manifest" if script_hashes else "inline_compat",
        "manifest_path": str(_manifest_path()),
        "script_hash_count": len(script_hashes),
        "style_hash_count": len(manifest["style_hashes"]),
        "allows_inline_script": "'unsafe-inline'" in header.partition("style-src")[0],
        "inline_bootstrap_reason": "" if script_hashes else _FALLBACK_REASON,
    }
