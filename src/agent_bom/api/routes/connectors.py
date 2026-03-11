"""Connectors, registry, and security lookup API routes.

Endpoints:
    GET  /v1/connectors                    list available SaaS connectors
    GET  /v1/connectors/{name}/health      connector health check
    GET  /v1/registry                      list MCP server registry
    GET  /v1/registry/{server_id}          get registry server entry
    GET  /v1/malicious/check               malicious package / typosquat check
    GET  /v1/scorecard/{eco}/{pkg}         OpenSSF Scorecard lookup
"""

from __future__ import annotations

import functools
import logging
import re as _re
from pathlib import Path as _Path

from fastapi import APIRouter, HTTPException

from agent_bom.security import sanitize_error

router = APIRouter()
_logger = logging.getLogger(__name__)


# ─── Registry helpers ────────────────────────────────────────────────────────


def _derive_name(key: str) -> str:
    """Derive a human-readable name from a registry key."""
    # Strip npm scope prefix
    name = _re.sub(r"^@[^/]+/", "", key)
    # Strip common prefixes
    for prefix in ("mcp-server-", "server-", "mcp-"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    # Title-case, replace hyphens with spaces
    return name.replace("-", " ").title()


def _infer_publisher(key: str) -> str:
    """Infer publisher from a registry key."""
    # npm scoped: @scope/pkg → scope
    m = _re.match(r"^@([^/]+)/", key)
    if m:
        return m.group(1)
    # Unscoped: use first segment before hyphen or the key itself
    return key.split("-")[0] if "-" in key else key


@functools.lru_cache(maxsize=1)
def _load_registry() -> list[dict]:
    """Load the bundled MCP registry JSON (cached after first load)."""
    import json as _json

    registry_path = _Path(__file__).parent.parent.parent / "mcp_registry.json"
    if not registry_path.exists():
        return []
    try:
        raw = _json.loads(registry_path.read_text())
    except (_json.JSONDecodeError, OSError):
        return []
    servers_dict = raw.get("servers", {})
    result = []
    for key, entry in servers_dict.items():
        result.append(
            {
                "id": key,
                "name": entry.get("name", _derive_name(key)),
                "publisher": _infer_publisher(key),
                "verified": entry.get("verified", False),
                "transport": "stdio",
                "risk_level": entry.get("risk_level", "low"),
                "packages": [{"name": entry["package"], "ecosystem": entry["ecosystem"]}] if entry.get("package") else [],
                "source_url": entry.get("source_url", ""),
                "description": entry.get("description"),
                "sigstore_bundle": None,
                "tools": entry.get("tools", []),
                "credential_env_vars": entry.get("credential_env_vars", []),
                "category": entry.get("category"),
                "license": entry.get("license"),
                "latest_version": entry.get("latest_version"),
                "known_cves": entry.get("known_cves", []),
                "command_patterns": entry.get("command_patterns", []),
                "risk_justification": entry.get("risk_justification"),
            }
        )
    return result


# ─── Connector endpoints ─────────────────────────────────────────────────────


@router.get("/v1/connectors", tags=["connectors"])
async def list_available_connectors() -> dict:
    """List available SaaS connectors for AI agent discovery."""
    from agent_bom.connectors import list_connectors

    return {"connectors": list_connectors()}


@router.get("/v1/connectors/{name}/health", tags=["connectors"])
async def connector_health(name: str) -> dict:
    """Check connectivity for a SaaS connector."""
    try:
        from agent_bom.connectors import check_connector_health

        status = check_connector_health(name)
        return {"connector": status.connector, "state": status.state.value, "message": status.message, "api_version": status.api_version}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=sanitize_error(str(exc))) from exc


# ─── Registry endpoints ──────────────────────────────────────────────────────


@router.get("/v1/registry", tags=["registry"])
async def list_registry() -> dict:
    """List all known MCP servers from the agent-bom registry."""
    servers = _load_registry()
    return {"servers": servers, "count": len(servers)}


@router.get("/v1/registry/{server_id:path}", tags=["registry"])
async def get_registry_server(server_id: str) -> dict:
    """Get a single MCP server entry by ID (e.g. 'modelcontextprotocol/filesystem')."""
    servers = _load_registry()
    for server in servers:
        if server.get("id") == server_id:
            return server
    raise HTTPException(status_code=404, detail=f"Registry entry '{server_id}' not found")


# ─── Security lookup endpoints ───────────────────────────────────────────────


@router.get("/v1/malicious/check", tags=["security"])
async def check_malicious(name: str, ecosystem: str = "npm") -> dict:
    """Check if a package name is a known malicious package or typosquat.

    Query params:
        name: Package name to check
        ecosystem: Package ecosystem (npm, pypi)
    """
    from agent_bom.malicious import check_typosquat

    typosquat_target = check_typosquat(name, ecosystem)
    return {
        "package": name,
        "ecosystem": ecosystem,
        "is_typosquat": typosquat_target is not None,
        "typosquat_target": typosquat_target,
    }


@router.get("/v1/scorecard/{ecosystem}/{package:path}", tags=["security"])
async def scorecard_lookup(ecosystem: str, package: str) -> dict:
    """Look up OpenSSF Scorecard for a package.

    Resolves the package's source repository and fetches its scorecard
    from api.securityscorecards.dev.

    Path params:
        ecosystem: Package ecosystem (npm, pypi, go, cargo)
        package: Package name
    """
    import re as _re_local

    from agent_bom.scorecard import extract_github_repo, fetch_scorecard

    # Validate package input — only allow safe characters
    if not _re_local.match(r"^[A-Za-z0-9._@/:-]+$", package):
        raise HTTPException(status_code=400, detail="Invalid package name")

    # For GitHub-hosted packages, try direct repo lookup
    # Common patterns: npm @scope/pkg -> github.com/scope/pkg
    repo = None

    # Try direct GitHub repo format
    if "/" in package:
        repo = package

    if not repo:
        # Try ecosystem-specific heuristics
        if ecosystem == "npm":
            # npm packages often map to github.com/owner/repo
            # Strip @ scope prefix for GitHub lookup
            clean = package.lstrip("@").replace("/", "/")
            repo = clean
        elif ecosystem == "pypi":
            # PyPI packages often use the package name as the repo
            repo = None  # Need source_repo metadata
        elif ecosystem == "go":
            # Go modules are their repo path
            repo_match = extract_github_repo(f"https://{package}")
            if repo_match:
                repo = repo_match

    if not repo:
        return {
            "package": package,
            "ecosystem": ecosystem,
            "scorecard": None,
            "error": "Could not resolve GitHub repository for this package. "
            "Try providing the GitHub owner/repo directly (e.g., /v1/scorecard/github/expressjs/express).",
        }

    data = await fetch_scorecard(repo)
    if data is None:
        return {
            "package": package,
            "ecosystem": ecosystem,
            "repo": repo,
            "scorecard": None,
            "error": f"No scorecard found for github.com/{repo}",
        }

    return {
        "package": package,
        "ecosystem": ecosystem,
        "repo": repo,
        "scorecard": data,
    }
