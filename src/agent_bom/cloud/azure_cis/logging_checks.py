"""CIS Azure section 5 — activity log alerts and PostgreSQL logging checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage
from ..aws_inventory import is_access_denied_error
from ._base import (
    _LOGGING_SECTION,
    _pass_or_no_data,
    logger,
)


def _check_5_1_2(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.2 — Ensure Activity Log retention is set to at least 365 days."""
    result = CISCheckResult(
        check_id="5.1.2",
        title="Activity Log retention 365 days or greater",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Update the retention policy on the Activity Log profile or Diagnostic Setting to retain logs for at least 365 days."
        ),
        cis_section=_LOGGING_SECTION,
    )
    try:
        profiles = list(monitor_client.log_profiles.list())
        if not profiles:
            result.status = CheckStatus.FAIL
            result.evidence = "No log profile found. Activity Log retention cannot be verified."
            return result

        failing = []
        for profile in profiles:
            retention = getattr(profile, "retention_policy", None)
            if retention:
                days = getattr(retention, "days", 0) or 0
                enabled = getattr(retention, "enabled", False)
                if enabled and days < 365:
                    failing.append(f"{profile.name} ({days} days)")
                elif not enabled:
                    failing.append(f"{profile.name} (retention disabled — indefinite)")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Log profiles with insufficient retention: {', '.join(failing)}"
        else:
            _pass_or_no_data(
                result, len(profiles), "log profile", f"All {len(profiles)} log profile(s) have retention ≥ 365 days or indefinite."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log profile retention: {exc}"
    return result


def _check_activity_log_alert(monitor_client: Any, check_id: str, title: str, operation_name: str) -> CISCheckResult:
    """Helper for Activity Log alert checks (5.1.3-5.1.6)."""
    result = CISCheckResult(
        check_id=check_id,
        title=title,
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=f"Create an Activity Log alert for the operation '{operation_name}'.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())
        found = False
        for alert in alerts:
            enabled = getattr(alert, "enabled", True)
            if not enabled:
                continue
            condition = getattr(alert, "condition", None)
            all_of = getattr(condition, "all_of", []) if condition else []
            for cond in all_of or []:
                field_name = getattr(cond, "field", "") or ""
                equals_val = getattr(cond, "equals", "") or ""
                if field_name.lower() == "operationname" and equals_val.lower() == operation_name.lower():
                    found = True
                    break
            if found:
                break
        if found:
            result.status = CheckStatus.PASS
            result.evidence = f"Activity Log alert found for operation '{operation_name}'."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"No Activity Log alert found for operation '{operation_name}'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Activity Log alerts: {exc}"
    return result


def _check_5_1_3(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.3 — Ensure Activity Log alert exists for Create or Update Key Vault."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.3",
        "Activity Log alert for Key Vault create/update",
        "Microsoft.KeyVault/vaults/write",
    )


def _check_5_1_4(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.4 — Ensure Activity Log alert exists for Delete Key Vault."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.4",
        "Activity Log alert for Key Vault delete",
        "Microsoft.KeyVault/vaults/delete",
    )


def _check_5_1_5(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.5 — Ensure Activity Log alert exists for Create or Update Network Security Group."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.5",
        "Activity Log alert for NSG create/update",
        "Microsoft.Network/networkSecurityGroups/write",
    )


def _check_5_1_6(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.6 — Ensure Activity Log alert exists for Delete Network Security Group."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.6",
        "Activity Log alert for NSG delete",
        "Microsoft.Network/networkSecurityGroups/delete",
    )


def _check_5_2_1(postgresql_client: Any) -> CISCheckResult:
    """CIS 5.2.1 — Ensure server parameter 'log_connections' is set to ON for PostgreSQL."""
    result = CISCheckResult(
        check_id="5.2.1",
        title="PostgreSQL Server log_connections parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'log_connections' server parameter to 'ON' on all PostgreSQL servers.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_connections")
                inspected += 1
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check log_connections for PostgreSQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_connections off: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.DBforPostgreSQL/servers/configurations/read",
                resource_kind="PostgreSQL server",
                pass_evidence=f"All {len(servers)} PostgreSQL server(s) have log_connections enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_connections setting: {exc}"
    return result


def _check_5_2_2(postgresql_client: Any) -> CISCheckResult:
    """CIS 5.2.2 — Ensure server parameter 'log_disconnections' is set to ON."""
    result = CISCheckResult(
        check_id="5.2.2",
        title="PostgreSQL Server log_disconnections parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'log_disconnections' server parameter to 'ON' on all PostgreSQL servers.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_disconnections")
                inspected += 1
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check log_disconnections for PostgreSQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_disconnections off: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.DBforPostgreSQL/servers/configurations/read",
                resource_kind="PostgreSQL server",
                pass_evidence=f"All {len(servers)} PostgreSQL server(s) have log_disconnections enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_disconnections setting: {exc}"
    return result


def _check_5_2_3(postgresql_client: Any) -> CISCheckResult:
    """CIS 5.2.3 — Ensure server parameter 'connection_throttling' is set to ON."""
    result = CISCheckResult(
        check_id="5.2.3",
        title="PostgreSQL Server connection_throttling parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'connection_throttling' server parameter to 'ON' on all PostgreSQL servers.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "connection_throttling")
                inspected += 1
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check connection_throttling for PostgreSQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with connection_throttling off: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.DBforPostgreSQL/servers/configurations/read",
                resource_kind="PostgreSQL server",
                pass_evidence=f"All {len(servers)} PostgreSQL server(s) have connection_throttling enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL connection_throttling setting: {exc}"
    return result
