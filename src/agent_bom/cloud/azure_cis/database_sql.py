"""CIS Azure section 4.1/4.2.1 — Azure SQL server checks."""

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


def _check_4_1_1(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.1 — Ensure auditing is set to On for SQL servers."""
    result = CISCheckResult(
        check_id="4.1.1",
        title="Auditing enabled on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable auditing on all Azure SQL servers to track database events and write them to an audit log.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
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
                logger.debug("Could not extract resource group from SQL server %s", server_name)
                continue

            try:
                audit_settings = sql_client.server_blob_auditing_policies.get(resource_group, server_name)
                inspected += 1
                state = getattr(audit_settings, "state", None)
                if _enum_text(state).lower() != "enabled":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check auditing for SQL server %s: %s", server_name, sanitize_text(exc))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without auditing enabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Sql/servers/auditingSettings/read",
                resource_kind="SQL server",
                pass_evidence=f"All {len(servers)} SQL server(s) have auditing enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server auditing settings: {exc}"
    return result


def _check_4_2_1(sql_client: Any) -> CISCheckResult:
    """CIS 4.2.1 — Ensure TLS version is set to TLSV1.2 for MySQL/PostgreSQL flexible servers."""
    result = CISCheckResult(
        check_id="4.2.1",
        title="TLS 1.2 or higher on database servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the minimum TLS version to TLS 1.2 on all Azure SQL, MySQL, and PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            min_tls = getattr(server, "minimal_tls_version", None)
            min_tls_str = _enum_text(min_tls)
            # Acceptable values: "1.2", "Tls1.2", "TLS1.2", etc.
            if min_tls_str and "1.2" not in min_tls_str and "1.3" not in min_tls_str:
                failing.append(f"{server_name} (TLS: {min_tls_str})")
            elif not min_tls_str:
                failing.append(f"{server_name} (TLS version not set)")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Servers without TLS 1.2+: {', '.join(failing)}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            _pass_or_no_data(result, len(servers), "SQL server", f"All {len(servers)} SQL server(s) enforce TLS 1.2 or higher.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check database server TLS settings: {exc}"
    return result


def _check_4_1_2(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.2 — Ensure SQL Server Transparent Data Encryption is enabled."""
    result = CISCheckResult(
        check_id="4.1.2",
        title="Transparent Data Encryption enabled on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Transparent Data Encryption on all SQL databases.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
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
                enc_protectors = sql_client.encryption_protectors.get(resource_group, server_name)
                inspected += 1
                _ = getattr(enc_protectors, "kind", "") or ""  # noqa: F841
                server_key_type = getattr(enc_protectors, "server_key_type", "") or ""
                if not server_key_type:
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check TDE for SQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without TDE configured: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Sql/servers/encryptionProtector/read",
                resource_kind="SQL server",
                pass_evidence=f"All {len(servers)} SQL server(s) have Transparent Data Encryption configured.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server TDE settings: {exc}"
    return result


def _check_4_1_3(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.3 — Ensure SQL Server Active Directory Admin is configured."""
    result = CISCheckResult(
        check_id="4.1.3",
        title="Azure AD admin configured for SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure an Azure AD administrator for each SQL server to enable centralized authentication.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
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
                admins = list(sql_client.server_azure_ad_administrators.list_by_server(resource_group, server_name))
                inspected += 1
                if not admins:
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check AD admin for SQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without Azure AD admin: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Sql/servers/administrators/read",
                resource_kind="SQL server",
                pass_evidence=f"All {len(servers)} SQL server(s) have Azure AD admin configured.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server AD admin settings: {exc}"
    return result


def _check_4_1_4(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.4 — Ensure Advanced Threat Protection is enabled for SQL servers."""
    result = CISCheckResult(
        check_id="4.1.4",
        title="Advanced Threat Protection enabled on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Advanced Threat Protection on all SQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
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
                atp = sql_client.server_advanced_threat_protection_settings.get(resource_group, server_name)
                inspected += 1
                state = getattr(atp, "state", "") or ""
                if _enum_text(state).lower() != "enabled":
                    failing.append(server_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(server_name)
                logger.debug("Could not check ATP for SQL server %s: %s", server_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without Advanced Threat Protection: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Sql/servers/advancedThreatProtectionSettings/read",
                resource_kind="SQL server",
                pass_evidence=f"All {len(servers)} SQL server(s) have Advanced Threat Protection enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server ATP settings: {exc}"
    return result


def _check_4_1_5(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.5 — Ensure SQL Server Vulnerability Assessment is configured."""
    result = CISCheckResult(
        check_id="4.1.5",
        title="Vulnerability Assessment configured on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure Vulnerability Assessment on all SQL servers with a storage account for scan results.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
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
                va = sql_client.server_vulnerability_assessments.get(resource_group, server_name)
                storage_path = getattr(va, "storage_container_path", "") or ""
                if not storage_path:
                    failing.append(server_name)
            except Exception:
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without Vulnerability Assessment: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(servers), "SQL server", f"All {len(servers)} SQL server(s) have Vulnerability Assessment configured."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server Vulnerability Assessment settings: {exc}"
    return result


def _check_4_1_6(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.6 — Ensure SQL server public network access is disabled."""
    result = CISCheckResult(
        check_id="4.1.6",
        title="Public network access disabled on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Disable public network access on SQL servers and use private endpoints for connectivity.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            public_access = getattr(server, "public_network_access", "") or ""
            if _enum_text(public_access).lower() != "disabled":
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers with public network access enabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(servers), "SQL server", f"All {len(servers)} SQL server(s) have public network access disabled.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server public network access: {exc}"
    return result
