"""Current approval overlays; persisted scan flags are historical evidence only."""

from typing import Any

from agent_bom.api.stores import _get_exception_store
from agent_bom.api.suppression_approval import suppression_active


def project_current_suppressions(rows: list[dict[str, Any]], tenant_id: str) -> list[dict[str, Any]]:
    """Revalidate a bounded read page without rewriting its original receipts."""
    approved = [exc for exc in _get_exception_store().list_all(tenant_id=tenant_id) if suppression_active(exc)]
    by_scope: dict[tuple[str, str], list[Any]] = {}
    for exc in approved:
        by_scope.setdefault((exc.vuln_id, exc.package_name), []).append(exc)
    projected = []
    for original in rows:
        row = dict(original)
        raw_evidence = row.get("evidence")
        evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
        vuln = str(row.get("vulnerability_id") or row.get("cve_id") or "")
        package = str(row.get("package_name") or row.get("package") or evidence.get("package_name") or "")
        name, separator, _version = package.rpartition("@")
        package_name = name if separator and name else package
        servers = [str(row.get("server_name") or ""), *(row.get("affected_servers") or [])]
        match = next(
            (
                exc
                for key in dict.fromkeys([(vuln, package), (vuln, package_name)])
                for exc in by_scope.get(key, [])
                if exc.server_name in {"", "*"} or exc.server_name in servers
            ),
            None,
        )
        historical = bool(
            row.get("suppressed")
            or row.get("vex_suppressed")
            or (row.get("risk_score") == 0 and row.get("vex_status") in {"not_affected", "fixed"})
        )
        if historical:
            # A missing original score is unknown, never a clean zero.
            row["risk_score"] = row.get("unsuppressed_risk_score") or evidence.get("unsuppressed_risk_score")
        if match is not None or historical:
            row["suppressed"] = match is not None
            row["actionable"] = match is None
            row["suppression_id"] = match.exception_id if match else None
            row["suppression_reason"] = match.reason if match else None
            row["suppression_state"] = "approved" if match else None
            if match:
                row["unsuppressed_risk_score"] = row.get("risk_score")
                row["risk_score"] = 0.0
        if "vex_suppressed" in row:
            row["vex_suppressed"] = False
        projected.append(row)
    return projected
