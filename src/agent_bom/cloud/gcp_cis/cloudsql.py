"""CIS GCP 6.x: Cloud SQL instance configuration."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _SQL_SECTION,
    _gcp_cloud_sql_instances,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_6_1(project_id: str) -> CISCheckResult:
    """CIS 6.1 — Ensure Cloud SQL database instances require all incoming connections to use SSL."""
    result = CISCheckResult(
        check_id="6.1",
        title="Cloud SQL requires SSL for all connections",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'Require SSL' (requireSsl) on all Cloud SQL instances to encrypt connections in transit.",
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        for inst in instances:
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            ip_config = settings.get("ipConfiguration", {})
            require_ssl = ip_config.get("requireSsl", False)
            if not require_ssl:
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Cloud SQL instances not requiring SSL ({len(failing)}/{len(instances)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(instances)} Cloud SQL instance(s) require SSL connections."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud SQL SSL configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_6_2(project_id: str) -> CISCheckResult:
    """CIS 6.2 — Ensure Cloud SQL database instances do not have public IPs."""
    result = CISCheckResult(
        check_id="6.2",
        title="Cloud SQL instances lack public IPs",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove public IP addresses from Cloud SQL instances and use private IP or Cloud SQL Proxy instead.",
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        for inst in instances:
            name = inst.get("name", "unknown")
            ip_addresses = inst.get("ipAddresses", [])
            for ip in ip_addresses:
                if ip.get("type") == "PRIMARY":
                    failing.append(name)
                    break

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Cloud SQL instances with public IPs ({len(failing)}/{len(instances)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No Cloud SQL instances have public IP addresses across {len(instances)} instance(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud SQL public IPs: {sanitize_discovery_warning(exc)}"
    return result


def _check_6_3(project_id: str) -> CISCheckResult:
    """CIS 6.3 — Ensure Cloud SQL database instances have automated backups enabled."""
    result = CISCheckResult(
        check_id="6.3",
        title="Cloud SQL automated backups enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable automated backups on all Cloud SQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        for inst in instances:
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            backup_config = settings.get("backupConfiguration", {})
            if not backup_config.get("enabled", False):
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Cloud SQL instances without automated backups ({len(failing)}/{len(instances)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(instances)} Cloud SQL instance(s) have automated backups enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud SQL backup configuration: {sanitize_discovery_warning(exc)}"
    return result


def _check_6_4(project_id: str) -> CISCheckResult:
    """CIS 6.4 — Ensure Cloud SQL PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter."""
    result = CISCheckResult(
        check_id="6.4",
        title="Cloud SQL PostgreSQL log_error_verbosity DEFAULT or stricter",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_error_verbosity database flag to DEFAULT or TERSE on PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        acceptable_values = {"default", "terse"}
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_error_verbosity":
                    flag_value = flag.get("value", "").lower()
                    break
            if flag_value is None or flag_value not in acceptable_values:
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without proper log_error_verbosity: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_error_verbosity: {sanitize_discovery_warning(exc)}"
    return result


def _check_6_5(project_id: str) -> CISCheckResult:
    """CIS 6.5 — Ensure Cloud SQL PostgreSQL instances have log_connections enabled."""
    result = CISCheckResult(
        check_id="6.5",
        title="Cloud SQL PostgreSQL log_connections flag on",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_connections database flag to 'on' on all PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_connections":
                    flag_value = flag.get("value", "").lower()
                    break
            if flag_value != "on":
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without log_connections enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_connections enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_connections: {sanitize_discovery_warning(exc)}"
    return result


def _check_6_6(project_id: str) -> CISCheckResult:
    """CIS 6.6 — Ensure Cloud SQL PostgreSQL instances have log_disconnections enabled."""
    result = CISCheckResult(
        check_id="6.6",
        title="Cloud SQL PostgreSQL log_disconnections flag on",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_disconnections database flag to 'on' on all PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_disconnections":
                    flag_value = flag.get("value", "").lower()
                    break
            if flag_value != "on":
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without log_disconnections enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_disconnections enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_disconnections: {sanitize_discovery_warning(exc)}"
    return result


def _check_6_7(project_id: str) -> CISCheckResult:
    """CIS 6.7 — Ensure Cloud SQL PostgreSQL instances have log_min_duration_statement set to -1."""
    result = CISCheckResult(
        check_id="6.7",
        title="Cloud SQL PostgreSQL log_min_duration_statement set to -1",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_min_duration_statement database flag to '-1' to disable logging of statement durations (prevents sensitive data leakage).",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_SQL_SECTION,
    )
    try:
        instances = _gcp_cloud_sql_instances(project_id)

        failing: list[str] = []
        for inst in instances:
            db_type = inst.get("databaseVersion", "")
            if not db_type.upper().startswith("POSTGRES"):
                continue
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            db_flags = settings.get("databaseFlags", [])
            flag_value = None
            for flag in db_flags:
                if flag.get("name") == "log_min_duration_statement":
                    flag_value = flag.get("value", "")
                    break
            if flag_value != "-1":
                failing.append(name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL instances without log_min_duration_statement=-1: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All PostgreSQL instances have log_min_duration_statement set to -1."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_min_duration_statement: {sanitize_discovery_warning(exc)}"
    return result
