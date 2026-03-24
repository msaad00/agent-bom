"""Scan history: save, load, and diff AI-BOM reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

HISTORY_DIR = Path.home() / ".agent-bom" / "history"


def history_dir() -> Path:
    """Return (and create) the history directory."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    return HISTORY_DIR


def save_report(report_json: dict, label: Optional[str] = None) -> Path:
    """Save a report dict to the history directory.

    Returns the path written to.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    stem = f"{ts}-{label}" if label else ts
    path = history_dir() / f"{stem}.json"
    path.write_text(json.dumps(report_json, indent=2))
    return path


def list_reports() -> list[Path]:
    """Return all saved report paths, newest first."""
    return sorted(history_dir().glob("*.json"), reverse=True)


def load_report(path: Path) -> dict:
    """Load a saved report JSON file."""
    return json.loads(path.read_text())


def latest_report() -> Optional[Path]:
    """Return the most recently saved report path, or None."""
    reports = list_reports()
    return reports[0] if reports else None


# ─── Diffing ────────────────────────────────────────────────────────────────


def _vuln_key(vuln: dict) -> tuple:
    """Stable key for a vulnerability entry in the JSON report."""
    return (vuln.get("id", ""), vuln.get("package", ""), vuln.get("ecosystem", ""))


def _extract_blast_vulns(report: dict) -> dict[tuple, dict]:
    """Build a map of vuln_key → blast_radius entry from a report dict."""
    result = {}
    for br in report.get("blast_radius", []):
        key = (
            br.get("vulnerability_id", ""),
            br.get("package", ""),
            br.get("ecosystem", ""),
        )
        result[key] = br
    return result


def diff_reports(baseline: dict, current: dict) -> dict:
    """Diff two report dicts (baseline vs current scan).

    Returns a dict with:
      new       – findings in current not in baseline
      resolved  – findings in baseline not in current
      unchanged – findings in both
      summary   – human-readable counts
    """
    baseline_vulns = _extract_blast_vulns(baseline)
    current_vulns = _extract_blast_vulns(current)

    baseline_keys = set(baseline_vulns)
    current_keys = set(current_vulns)

    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    unchanged_keys = baseline_keys & current_keys

    new = [current_vulns[k] for k in sorted(new_keys)]
    resolved = [baseline_vulns[k] for k in sorted(resolved_keys)]
    unchanged = [current_vulns[k] for k in sorted(unchanged_keys)]

    # Package-level changes
    baseline_pkgs = _extract_packages(baseline)
    current_pkgs = _extract_packages(current)
    new_pkgs = sorted(current_pkgs - baseline_pkgs)
    removed_pkgs = sorted(baseline_pkgs - current_pkgs)

    return {
        "baseline_generated_at": baseline.get("generated_at", "unknown"),
        "current_generated_at": current.get("generated_at", "unknown"),
        "new": new,
        "resolved": resolved,
        "unchanged": unchanged,
        "new_packages": new_pkgs,
        "removed_packages": removed_pkgs,
        "inventory_diff": _diff_inventory(baseline, current),
        "summary": {
            "new_findings": len(new),
            "resolved_findings": len(resolved),
            "unchanged_findings": len(unchanged),
            "new_packages": len(new_pkgs),
            "removed_packages": len(removed_pkgs),
        },
    }


def _extract_packages(report: dict) -> set[str]:
    """Extract set of 'ecosystem:name@version' strings from a report."""
    pkgs = set()
    for agent in report.get("agents", []):
        for server in agent.get("mcp_servers", []):
            for pkg in server.get("packages", []):
                key = f"{pkg.get('ecosystem', 'unknown')}:{pkg.get('name', '')}@{pkg.get('version', '')}"
                pkgs.add(key)
    return pkgs


def _get_inventory_snapshot(report: dict) -> dict:
    """Return inventory snapshot from a report, deriving a minimal one if absent."""
    snapshot = report.get("inventory_snapshot")
    if snapshot:
        return snapshot

    agents: list[dict] = []
    servers: list[dict] = []
    tools: list[dict] = []
    resources: list[dict] = []
    packages: list[dict] = []

    seen_servers: set[str] = set()
    seen_tools: set[str] = set()
    seen_resources: set[str] = set()
    seen_packages: set[str] = set()

    for agent in report.get("agents", []):
        agent_id = agent.get("stable_id") or agent.get("name", "")
        agents.append({"id": agent_id, "name": agent.get("name", ""), "status": agent.get("status", "")})
        for server in agent.get("mcp_servers", []):
            server_id = server.get("stable_id") or server.get("name", "")
            if server_id and server_id not in seen_servers:
                servers.append(
                    {
                        "id": server_id,
                        "name": server.get("name", ""),
                        "fingerprint": server.get("fingerprint", ""),
                    }
                )
                seen_servers.add(server_id)
            for tool in server.get("tools", []):
                tool_id = tool.get("stable_id") or tool.get("name", "")
                if tool_id and tool_id not in seen_tools:
                    tools.append({"id": tool_id, "name": tool.get("name", "")})
                    seen_tools.add(tool_id)
            for resource in server.get("resources", []):
                resource_id = resource.get("stable_id") or resource.get("uri", "")
                if resource_id and resource_id not in seen_resources:
                    resources.append({"id": resource_id, "uri": resource.get("uri", "")})
                    seen_resources.add(resource_id)
            for pkg in server.get("packages", []):
                pkg_id = pkg.get("stable_id") or f"{pkg.get('ecosystem', 'unknown')}:{pkg.get('name', '')}@{pkg.get('version', '')}"
                if pkg_id and pkg_id not in seen_packages:
                    packages.append({"id": pkg_id, "name": pkg.get("name", ""), "version": pkg.get("version", "")})
                    seen_packages.add(pkg_id)

    return {
        "agents": agents,
        "servers": servers,
        "tools": tools,
        "resources": resources,
        "packages": packages,
    }


def _diff_inventory(baseline: dict, current: dict) -> dict:
    """Diff deterministic inventory entities across two reports."""
    base_snapshot = _get_inventory_snapshot(baseline)
    curr_snapshot = _get_inventory_snapshot(current)

    result: dict[str, object] = {"changed_servers": []}
    summary: dict[str, int] = {}

    for entity_type in ("agents", "servers", "tools", "resources", "packages"):
        base_map = {item.get("id", ""): item for item in base_snapshot.get(entity_type, []) if item.get("id")}
        curr_map = {item.get("id", ""): item for item in curr_snapshot.get(entity_type, []) if item.get("id")}
        new_ids = sorted(set(curr_map) - set(base_map))
        removed_ids = sorted(set(base_map) - set(curr_map))
        result[f"new_{entity_type}"] = [curr_map[i] for i in new_ids]
        result[f"removed_{entity_type}"] = [base_map[i] for i in removed_ids]
        summary[f"new_{entity_type}"] = len(new_ids)
        summary[f"removed_{entity_type}"] = len(removed_ids)

    base_servers = {item.get("id", ""): item for item in base_snapshot.get("servers", []) if item.get("id")}
    curr_servers = {item.get("id", ""): item for item in curr_snapshot.get("servers", []) if item.get("id")}
    changed_servers = []
    for server_id in sorted(set(base_servers) & set(curr_servers)):
        base_fp = base_servers[server_id].get("fingerprint")
        curr_fp = curr_servers[server_id].get("fingerprint")
        if base_fp and curr_fp and base_fp != curr_fp:
            changed_servers.append(
                {
                    "id": server_id,
                    "name": curr_servers[server_id].get("name", ""),
                    "previous_fingerprint": base_fp,
                    "current_fingerprint": curr_fp,
                }
            )
    result["changed_servers"] = changed_servers
    summary["changed_servers"] = len(changed_servers)
    result["summary"] = summary
    return result
