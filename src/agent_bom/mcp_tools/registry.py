"""Registry tools — registry_lookup, marketplace_check, fleet_scan implementations."""

from __future__ import annotations

import json
import logging

from agent_bom.mcp_errors import (
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_RESOURCE,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    CODE_VALIDATION_INVALID_ECOSYSTEM,
    CODE_VALIDATION_MISSING_REQUIRED,
    mcp_error_json,
)

logger = logging.getLogger(__name__)


def registry_lookup_impl(
    *,
    server_name: str | None = None,
    package_name: str | None = None,
    _get_registry_data,
) -> str:
    """Implementation of the registry_lookup tool."""
    search_term = (server_name or package_name or "").strip()
    if not search_term:
        return mcp_error_json(
            CODE_VALIDATION_MISSING_REQUIRED,
            "Provide server_name or package_name.",
            details={"required_one_of": ["server_name", "package_name"]},
        )

    try:
        data = _get_registry_data()
    except Exception as exc:
        logger.exception("Registry read failed")
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, exc, details={"upstream": "mcp_registry"})

    servers = data.get("servers", {})
    search_lower = search_term.lower()

    for key, entry in servers.items():
        if search_lower in key.lower() or search_lower in entry.get("package", "").lower() or search_lower in entry.get("name", "").lower():
            return json.dumps(
                {
                    "found": True,
                    "id": key,
                    "name": entry.get("name", key),
                    "package": entry.get("package", ""),
                    "ecosystem": entry.get("ecosystem", ""),
                    "latest_version": entry.get("latest_version", ""),
                    "risk_level": entry.get("risk_level", "unknown"),
                    "risk_justification": entry.get("risk_justification", ""),
                    "verified": entry.get("verified", False),
                    "tools": entry.get("tools", []),
                    "credential_env_vars": entry.get("credential_env_vars", []),
                    "known_cves": entry.get("known_cves", []),
                    "category": entry.get("category", ""),
                    "license": entry.get("license", ""),
                    "source_url": entry.get("source_url", ""),
                },
                indent=2,
            )

    return mcp_error_json(
        CODE_NOT_FOUND_RESOURCE,
        "No matching server found in registry.",
        details={"query": search_term, "scope": "mcp_registry"},
    )


async def marketplace_check_impl(
    *,
    package: str,
    ecosystem: str = "npm",
    _validate_ecosystem,
    _get_registry_data_raw,
    _truncate_response,
) -> str:
    """Implementation of the marketplace_check tool."""
    try:
        name = package.strip()
        if not name or len(name) > 200:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                "Invalid package name. Must be 1-200 characters.",
                details={"argument": "package"},
            )

        try:
            eco = _validate_ecosystem(ecosystem)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return mcp_error_json(CODE_VALIDATION_INVALID_ECOSYSTEM, exc, details={"argument": "ecosystem"})

        # Fetch package metadata from registry
        from agent_bom.http_client import create_client

        version = "unknown"
        download_count = 0
        license_info = None

        async with create_client(timeout=15.0) as client:
            if eco == "npm":
                try:
                    resp = await client.get(f"https://registry.npmjs.org/{name}")
                    if resp.status_code == 200:
                        data = resp.json()
                        dist_tags = data.get("dist-tags", {})
                        version = dist_tags.get("latest", "unknown")
                        license_info = data.get("license")
                except Exception:
                    logger.debug("npm registry lookup failed for %s", name)
                # npm download count
                try:
                    resp = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{name}")
                    if resp.status_code == 200:
                        download_count = resp.json().get("downloads", 0)
                except Exception:
                    logger.debug("npm download count lookup failed for %s", name)
            elif eco == "pypi":
                try:
                    resp = await client.get(f"https://pypi.org/pypi/{name}/json")
                    if resp.status_code == 200:
                        data = resp.json()
                        version = data.get("info", {}).get("version", "unknown")
                        license_info = data.get("info", {}).get("license")
                except Exception:
                    logger.debug("PyPI metadata lookup failed for %s", name)

        # Check CVEs
        from agent_bom.models import Package as Pkg
        from agent_bom.scanners import build_vulnerabilities, query_osv_batch

        pkg = Pkg(name=name, version=version, ecosystem=eco)
        results = await query_osv_batch([pkg])
        key = f"{eco}:{name}@{version}"
        vuln_data = results.get(key, [])
        vulns = build_vulnerabilities(vuln_data, pkg) if vuln_data else []

        # Cross-reference MCP registry
        registry_verified = False
        try:
            data_raw = _get_registry_data_raw()
            registry = json.loads(data_raw)
            if isinstance(registry, dict):
                servers = registry.get("servers", registry)
                for _k, v in servers.items() if isinstance(servers, dict) else []:
                    pkgs = v.get("packages", [])
                    if name in pkgs or any(name in p for p in pkgs):
                        registry_verified = True
                        break
        except Exception:
            logger.debug("MCP registry verification failed for %s", name)

        # Build trust signals
        trust_signals = []
        if len(vulns) == 0:
            trust_signals.append("no-known-cves")
        if registry_verified:
            trust_signals.append("registry-verified")
        if download_count > 100_000:
            trust_signals.append("high-adoption")
        elif download_count > 10_000:
            trust_signals.append("moderate-adoption")
        if license_info:
            trust_signals.append(f"license:{license_info}")

        return json.dumps(
            {
                "package": name,
                "version": version,
                "ecosystem": eco,
                "cve_count": len(vulns),
                "download_count": download_count,
                "registry_verified": registry_verified,
                "license": license_info,
                "trust_signals": trust_signals,
                "vulnerabilities": [{"id": v.id, "severity": v.severity.value} for v in vulns[:10]],
            },
            indent=2,
            default=str,
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc)


async def fleet_scan_impl(
    *,
    servers: str,
    _truncate_response,
) -> str:
    """Implementation of the fleet_scan tool."""
    try:
        from agent_bom.fleet_scan import fleet_scan as _fleet_scan

        # Parse input: support comma-separated and newline-separated
        names: list[str] = []
        for line in servers.replace(",", "\n").split("\n"):
            name = line.strip()
            if name:
                names.append(name)

        if not names:
            return mcp_error_json(
                CODE_VALIDATION_MISSING_REQUIRED,
                "No server names provided.",
                details={"argument": "servers"},
            )

        if len(names) > 1000:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                f"Too many servers ({len(names)}). Maximum is 1,000 per request.",
                details={"argument": "servers", "count": len(names), "max": 1000},
            )

        result = _fleet_scan(names)
        return _truncate_response(result.to_json())
    except Exception as exc:
        logger.exception("MCP tool error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc)
