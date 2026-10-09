"""CIS Azure section 4.2/4.3 — MySQL and PostgreSQL server checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage
from ..aws_inventory import is_access_denied_error
from ._base import (
    _DATABASE_SECTION,
    _enum_text,
    _pass_or_no_data,
    logger,
)


def _check_4_2_2(mysql_client: Any) -> CISCheckResult:
    """CIS 4.2.2 — Ensure MySQL SSL enforcement is enabled."""
    result = CISCheckResult(
        check_id="4.2.2",
        title="SSL enforcement enabled on MySQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable SSL enforcement on all MySQL servers to ensure encrypted connections.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(mysql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            ssl_enforcement = getattr(server, "ssl_enforcement", "") or ""
            if _enum_text(ssl_enforcement).lower() != "enabled":
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"MySQL servers without SSL enforcement: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(servers), "MySQL server", f"All {len(servers)} MySQL server(s) have SSL enforcement enabled.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check MySQL SSL enforcement: {exc}"
    return result


def _check_4_2_3(mysql_client: Any) -> CISCheckResult:
    """CIS 4.2.3 — Ensure MySQL server parameter 'log_checkpoints' is enabled."""
    result = CISCheckResult(
        check_id="4.2.3",
        title="MySQL log_checkpoints parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_checkpoints' server parameter on all MySQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(mysql_client.servers.list())
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
                config = mysql_client.configurations.get(resource_group, server_name, "log_checkpoints")
                inspected += 1
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check log_checkpoints for MySQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"MySQL servers with log_checkpoints disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.DBforMySQL/servers/configurations/read",
                resource_kind="MySQL server",
                pass_evidence=f"All {len(servers)} MySQL server(s) have log_checkpoints enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check MySQL log_checkpoints setting: {exc}"
    return result


def _check_4_3_1(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.1 — Ensure PostgreSQL SSL enforcement is enabled."""
    result = CISCheckResult(
        check_id="4.3.1",
        title="SSL enforcement enabled on PostgreSQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable SSL enforcement on all PostgreSQL servers to ensure encrypted connections.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            ssl_enforcement = getattr(server, "ssl_enforcement", "") or ""
            if _enum_text(ssl_enforcement).lower() != "enabled":
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers without SSL enforcement: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(servers), "PostgreSQL server", f"All {len(servers)} PostgreSQL server(s) have SSL enforcement enabled."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL SSL enforcement: {exc}"
    return result


def _check_4_3_2(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.2 — Ensure PostgreSQL server parameter 'log_checkpoints' is enabled."""
    result = CISCheckResult(
        check_id="4.3.2",
        title="PostgreSQL log_checkpoints parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_checkpoints' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
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
                config = postgresql_client.configurations.get(resource_group, server_name, "log_checkpoints")
                inspected += 1
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check log_checkpoints for PostgreSQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_checkpoints disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.DBforPostgreSQL/servers/configurations/read",
                resource_kind="PostgreSQL server",
                pass_evidence=f"All {len(servers)} PostgreSQL server(s) have log_checkpoints enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_checkpoints setting: {exc}"
    return result


def _check_4_3_3(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.3 — Ensure PostgreSQL server parameter 'log_connections' is enabled."""
    result = CISCheckResult(
        check_id="4.3.3",
        title="PostgreSQL log_connections parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_connections' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
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
            result.evidence = f"PostgreSQL servers with log_connections disabled: {', '.join(failing)}"
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


def _check_4_3_4(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.4 — Ensure PostgreSQL server parameter 'log_disconnections' is enabled."""
    result = CISCheckResult(
        check_id="4.3.4",
        title="PostgreSQL log_disconnections parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_disconnections' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
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
            result.evidence = f"PostgreSQL servers with log_disconnections disabled: {', '.join(failing)}"
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


def _check_4_3_5(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.5 — Ensure PostgreSQL server parameter 'connection_throttling' is enabled."""
    result = CISCheckResult(
        check_id="4.3.5",
        title="PostgreSQL connection_throttling parameter set to ON",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'connection_throttling' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
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
            result.evidence = f"PostgreSQL servers with connection_throttling disabled: {', '.join(failing)}"
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
