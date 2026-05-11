"""Machine-readable CLI contract for assistant and automation callers."""

from __future__ import annotations

import json
import os
import sys
from copy import deepcopy
from typing import Any

AGENT_MODE_ENV_VAR = "AGENT_BOM_AGENT_MODE"
AGENT_MODE_SCHEMA_VERSION = "1"


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
    return {
        "agents": summary.get("agents", len(agents)),
        "servers": summary.get("servers", inventory.get("servers")),
        "packages": summary.get("packages", inventory.get("packages")),
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
) -> dict[str, Any]:
    """Wrap a scan report in the stable agent-mode success envelope."""
    payload, truncation = _truncate_report(report_json, token_budget)
    return {
        "schema_version": AGENT_MODE_SCHEMA_VERSION,
        "mode": "agent",
        "ok": exit_code == 0,
        "command": command,
        "exit_code": exit_code,
        "summary": _summary(report_json),
        "confidence": _confidence(report_json),
        "truncated": bool(truncation["truncated"]),
        "truncation": truncation,
        "data": payload,
    }


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
    return json.dumps(payload, indent=2, sort_keys=True, default=str)
