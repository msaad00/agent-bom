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
