"""Machine-readable CLI contract for assistant and automation callers."""

from __future__ import annotations

import json
import os
import sys
from copy import deepcopy
from typing import Any

AGENT_MODE_ENV_VAR = "AGENT_BOM_AGENT_MODE"
AGENT_MODE_SCHEMA_VERSION = "1"

# Number of top-ranked findings / exposure paths kept in the summarized scan
# payload that agent mode emits by default.
SCAN_SUMMARY_TOP_N = 10

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def agent_mode_requested(argv: list[str] | None = None) -> bool:
    """Return True when the current invocation requested agent mode."""
    args = sys.argv[1:] if argv is None else argv
    if "--agent-mode" in args:
        return True
    raw = os.environ.get(AGENT_MODE_ENV_VAR, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _severity_counts(report_json: dict[str, Any]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for item in report_json.get("blast_radius", []) or []:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or "unknown").lower()
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _summary(report_json: dict[str, Any]) -> dict[str, Any]:
    summary_raw = report_json.get("summary")
    summary: dict[str, Any] = summary_raw if isinstance(summary_raw, dict) else {}
    inventory_raw = report_json.get("inventory_snapshot")
    inventory: dict[str, Any] = inventory_raw if isinstance(inventory_raw, dict) else {}
    agents_raw = report_json.get("agents")
    agents: list[Any] = agents_raw if isinstance(agents_raw, list) else []
    blast_radius_raw = report_json.get("blast_radius")
    blast_radius: list[Any] = blast_radius_raw if isinstance(blast_radius_raw, list) else []
    findings_raw = report_json.get("findings")
    findings: list[Any] = findings_raw if isinstance(findings_raw, list) else []
    scorecard_raw = report_json.get("posture_scorecard")
    scorecard: dict[str, Any] = scorecard_raw if isinstance(scorecard_raw, dict) else {}
    inv_packages = inventory.get("packages")
    inv_servers = inventory.get("servers")
    return {
        "agents": summary.get("total_agents", summary.get("agents", len(agents))),
        "servers": summary.get(
            "total_mcp_servers",
            summary.get("servers", len(inv_servers) if isinstance(inv_servers, list) else inv_servers),
        ),
        "packages": summary.get(
            "total_packages",
            summary.get("packages") if isinstance(summary.get("packages"), int) else None,
        )
        or (len(inv_packages) if isinstance(inv_packages, list) else inv_packages),
        "vulnerabilities": summary.get("total_vulnerabilities", len(blast_radius)),
        "findings": len(findings),
        "severity_counts": _severity_counts(report_json),
        "posture_grade": report_json.get("posture_grade") or scorecard.get("grade"),
    }


def _confidence(report_json: dict[str, Any]) -> dict[str, Any]:
    sources_raw = report_json.get("scan_sources")
    sources: list[Any] = sources_raw if isinstance(sources_raw, list) else []
    blast_radius_raw = report_json.get("blast_radius")
    blast_radius: list[Any] = blast_radius_raw if isinstance(blast_radius_raw, list) else []
    has_advisory_backing = any(isinstance(item, dict) and item.get("vulnerability_id") for item in blast_radius)
    signals = [
        {"name": "schema_version", "present": bool(report_json.get("schema_version"))},
        {"name": "scan_sources", "present": bool(sources)},
        {"name": "advisory_backing", "present": has_advisory_backing},
    ]
    present = sum(1 for signal in signals if signal["present"])
    level = "high" if present >= 2 else "medium" if present == 1 else "low"
    return {"level": level, "signals": signals}


def _packages_by_ecosystem(report_json: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    inventory = report_json.get("inventory_snapshot")
    packages = inventory.get("packages") if isinstance(inventory, dict) else None
    if not isinstance(packages, list):
        packages = report_json.get("packages")
    for pkg in packages or []:
        if not isinstance(pkg, dict):
            continue
        ecosystem = str(pkg.get("ecosystem") or "unknown").lower()
        counts[ecosystem] = counts.get(ecosystem, 0) + 1
    return counts


def _severity_breakdown(items: list[Any], *severity_keys: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        severity = "unknown"
        for key in severity_keys:
            value = item.get(key)
            if value:
                severity = str(value).lower()
                break
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _risk_sort_key(item: Any) -> tuple[float, int]:
    if not isinstance(item, dict):
        return (0.0, 0)
    try:
        score = float(item.get("risk_score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    severity = str(item.get("effective_severity") or item.get("severity") or "unknown").lower()
    return (score, _SEVERITY_RANK.get(severity, 0))


def _compact_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "cve_id": item.get("cve_id"),
        "title": item.get("title"),
        "severity": item.get("effective_severity") or item.get("severity"),
        "risk_score": item.get("risk_score"),
        "is_kev": item.get("is_kev"),
        "finding_type": item.get("finding_type"),
        "asset": item.get("asset"),
        "fixed_version": item.get("fixed_version"),
    }


def _compact_exposure(item: dict[str, Any]) -> dict[str, Any]:
    affected = item.get("affected_agents")
    return {
        "vulnerability_id": item.get("vulnerability_id"),
        "package": item.get("package_name") or item.get("package"),
        "version": item.get("package_version"),
        "ecosystem": item.get("ecosystem"),
        "severity": item.get("severity_label") or item.get("severity"),
        "risk_score": item.get("risk_score"),
        "is_kev": item.get("is_kev"),
        "fixed_version": item.get("fixed_version"),
        "graph_reachable": item.get("graph_reachable"),
        "affected_agents": affected if isinstance(affected, list) else None,
    }


def _compact_agent(item: dict[str, Any]) -> dict[str, Any]:
    servers = item.get("mcp_servers")
    server_names = [s.get("name") for s in servers if isinstance(s, dict)] if isinstance(servers, list) else []
    return {
        "name": item.get("name"),
        "type": item.get("type"),
        "agent_type": item.get("agent_type"),
        "status": item.get("status"),
        "server_count": len(server_names),
        "servers": server_names[:25],
    }


def summarize_scan_data(
    report_json: dict[str, Any],
    *,
    top_n: int = SCAN_SUMMARY_TOP_N,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Build a bounded, machine-readable scan payload for automation callers.

    The default agent-mode scan payload omits the full inlined per-package
    provenance dump (``ai_inventory``, ``ai_bom_entities``, per-package
    ``discovery_provenance``, the full ``findings``/``packages`` lists, etc.)
    and replaces it with counts plus the top ``top_n`` ranked findings and
    exposure paths. Full detail stays available via ``--agent-mode-full`` or by
    writing the report to disk with ``-o``.
    """
    findings_raw = report_json.get("findings")
    findings: list[Any] = findings_raw if isinstance(findings_raw, list) else []
    blast_raw = report_json.get("blast_radius")
    blast_radius: list[Any] = blast_raw if isinstance(blast_raw, list) else []
    agents_raw = report_json.get("agents")
    agents: list[Any] = agents_raw if isinstance(agents_raw, list) else []
    scorecard_raw = report_json.get("posture_scorecard")
    scorecard: dict[str, Any] = scorecard_raw if isinstance(scorecard_raw, dict) else {}

    top_findings = sorted((f for f in findings if isinstance(f, dict)), key=_risk_sort_key, reverse=True)[:top_n]
    top_exposure = sorted((b for b in blast_radius if isinstance(b, dict)), key=_risk_sort_key, reverse=True)[:top_n]

    counts = dict(_summary(report_json))
    counts["packages_by_ecosystem"] = _packages_by_ecosystem(report_json)
    counts["findings_by_severity"] = _severity_breakdown(findings, "effective_severity", "severity")
    counts["exposure_by_severity"] = _severity_breakdown(blast_radius, "severity_label", "severity")

    return {
        "schema_version": report_json.get("schema_version"),
        "document_type": report_json.get("document_type"),
        "spec_version": report_json.get("spec_version"),
        "generated_at": report_json.get("generated_at"),
        "scan_id": report_json.get("scan_id"),
        "posture_grade": report_json.get("posture_grade") or scorecard.get("grade"),
        "counts": counts,
        "top_findings": [_compact_finding(f) for f in top_findings],
        "top_exposure_paths": [_compact_exposure(b) for b in top_exposure],
        "agents": [_compact_agent(a) for a in agents],
        "posture_scorecard": {
            "grade": scorecard.get("grade"),
            "score": scorecard.get("score"),
            "summary": scorecard.get("summary"),
        },
        "full_report": {
            "included": False,
            "output_path": output_path if output_path and output_path != "-" else None,
            "hint": (
                "Summarized payload. Re-run with --agent-mode-full for the complete report, "
                "or write full JSON to disk with `-o <file> --format json`."
            ),
        },
    }


def _truncate_report(report_json: dict[str, Any], token_budget: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """Trim largest report collections to fit an approximate token budget."""
    if token_budget <= 0:
        return report_json, {"enabled": False, "truncated": False, "token_budget": None, "approx_tokens": None, "removed": {}}

    payload = deepcopy(report_json)
    removed: dict[str, int] = {}

    def approx_tokens() -> int:
        return max(1, len(json.dumps(payload, separators=(",", ":"), default=str)) // 4)

    def trim_list(key: str) -> None:
        value = payload.get(key)
        if not isinstance(value, list) or len(value) <= 1:
            return
        keep = max(1, len(value) // 2)
        removed[key] = removed.get(key, 0) + len(value) - keep
        payload[key] = value[:keep]

    for key in ("findings", "blast_radius", "agents"):
        while approx_tokens() > token_budget and isinstance(payload.get(key), list) and len(payload[key]) > 1:
            trim_list(key)

    def record_removed(key: str, value: Any) -> None:
        removed[key] = removed.get(key, 0) + (len(value) if isinstance(value, list) else 1)

    for key in (
        "ai_bom_entities",
        "inventory_snapshot",
        "remediation_plan",
        "compliance_bundle",
        "graph",
        "lineage_graph",
        "attack_paths",
        "findings",
        "blast_radius",
        "agents",
    ):
        if approx_tokens() <= token_budget:
            break
        if key in payload:
            record_removed(key, payload.pop(key))

    if approx_tokens() > token_budget:
        compact_keys = (
            "schema_version",
            "document_type",
            "spec_version",
            "generated_at",
            "posture_grade",
            "posture_scorecard",
            "summary",
        )
        payload = {key: report_json[key] for key in compact_keys if key in report_json}
        removed["payload_compacted"] = 1

    final_tokens = approx_tokens()
    return payload, {
        "enabled": True,
        "truncated": bool(removed),
        "token_budget": token_budget,
        "approx_tokens": final_tokens,
        "removed": removed,
    }


def success_envelope(
    *,
    command: str,
    report_json: dict[str, Any],
    exit_code: int,
    token_budget: int = 0,
    full: bool = False,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Wrap a scan report in the stable agent-mode success envelope.

    By default the ``data`` field carries a bounded SUMMARY of the scan
    (counts plus top-ranked findings and exposure paths) so the payload fits an
    automation caller's context window. Pass ``full=True`` to inline the
    complete report (the legacy shape); ``data_mode`` records which shape was
    emitted.
    """
    if full:
        data, truncation = _truncate_report(report_json, token_budget)
        data_mode = "full"
    else:
        data, truncation = _truncate_report(summarize_scan_data(report_json, output_path=output_path), token_budget)
        data_mode = "summary"
    return {
        "schema_version": AGENT_MODE_SCHEMA_VERSION,
        "mode": "agent",
        "ok": exit_code == 0,
        "command": command,
        "data_mode": data_mode,
        "exit_code": exit_code,
        "summary": _summary(report_json),
        "confidence": _confidence(report_json),
        "truncated": bool(truncation["truncated"]),
        "truncation": truncation,
        "data": data,
    }


def command_success_envelope(
    *,
    command: str,
    data: dict[str, Any],
    exit_code: int,
    summary: dict[str, Any],
    confidence: dict[str, Any],
    error_type: str | None = None,
) -> dict[str, Any]:
    """Wrap a non-scan command payload in the stable agent-mode envelope."""
    payload = {
        "schema_version": AGENT_MODE_SCHEMA_VERSION,
        "mode": "agent",
        "ok": exit_code == 0,
        "command": command,
        "data_mode": "full",
        "exit_code": exit_code,
        "summary": summary,
        "confidence": confidence,
        "truncated": False,
        "truncation": {
            "enabled": False,
            "truncated": False,
            "token_budget": None,
            "approx_tokens": None,
            "removed": {},
        },
        "data": data,
    }
    if exit_code != 0:
        error = {
            "type": error_type or "command_exit",
            "message": str(data.get("message") or f"{command} exited with code {exit_code}"),
        }
        payload["error"] = error
        payload["errors"] = [error]
    return payload


def error_envelope(*, command: str | None, message: str, exit_code: int, error_type: str) -> dict[str, Any]:
    """Build the stable agent-mode error envelope."""
    error = {
        "type": error_type,
        "message": message,
    }
    return {
        "schema_version": AGENT_MODE_SCHEMA_VERSION,
        "mode": "agent",
        "ok": False,
        "command": command,
        "exit_code": exit_code,
        "truncated": False,
        "error": error,
        "errors": [error],
    }


def dumps_envelope(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
