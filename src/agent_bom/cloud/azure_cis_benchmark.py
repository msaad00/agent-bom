"""CIS Azure Security Benchmark v3.0 — live subscription checks.

Runs read-only Azure management API calls against the CIS Microsoft Azure
Foundations Benchmark v3.0 covering IAM, Defender for Cloud, Storage, Database
Services, Logging, Networking, Virtual Machines, Key Vault, and App Service.

Required permissions (all read-only, covered by Security Reader or Reader role):
    Microsoft.Authorization/roleAssignments/read
    Microsoft.Authorization/roleDefinitions/read
    Microsoft.Security/pricings/read
    Microsoft.Insights/diagnosticSettings/read
    Microsoft.Insights/logProfiles/read
    Microsoft.Insights/activityLogAlerts/read
    Microsoft.Network/networkSecurityGroups/read
    Microsoft.Network/networkWatchers/read
    Microsoft.Network/applicationGateways/read
    Microsoft.Network/frontDoors/read
    Microsoft.Storage/storageAccounts/read
    Microsoft.Storage/storageAccounts/blobServices/read
    Microsoft.Storage/storageAccounts/privateEndpointConnections/read
    Microsoft.Sql/servers/read
    Microsoft.Sql/servers/auditingSettings/read
    Microsoft.Sql/servers/advancedThreatProtectionSettings/read
    Microsoft.Sql/servers/vulnerabilityAssessments/read
    Microsoft.Sql/servers/administrators/read
    Microsoft.Sql/servers/encryptionProtector/read
    Microsoft.DBforMySQL/servers/read
    Microsoft.DBforPostgreSQL/servers/read
    Microsoft.DBforPostgreSQL/servers/configurations/read
    Microsoft.Compute/virtualMachines/read
    Microsoft.Compute/virtualMachines/extensions/read
    Microsoft.Compute/disks/read
    Microsoft.KeyVault/vaults/read
    Microsoft.KeyVault/vaults/keys/read
    Microsoft.KeyVault/vaults/secrets/read
    Microsoft.KeyVault/vaults/privateEndpointConnections/read
    Microsoft.Web/sites/read
    Microsoft.Web/sites/config/read

Authentication uses DefaultAzureCredential (env vars, managed identity,
Azure CLI login, VS Code credentials).

Install: ``pip install 'agent-bom[azure]'``
"""

from __future__ import annotations

import os
from typing import Any

from agent_bom.security import sanitize_text

from .aws_cis_benchmark import CheckStatus, CISCheckResult
from .aws_cis_benchmark import finalize_read_coverage as finalize_read_coverage
from .aws_inventory import is_access_denied_error as is_access_denied_error

# The checks live in ``agent_bom.cloud.azure_cis`` by CIS section; every name is
# re-exported here so imports and patch targets on this module keep working.
from .azure_cis._base import (
    _APPSERVICE_SECTION as _APPSERVICE_SECTION,
)
from .azure_cis._base import (
    _DATABASE_SECTION as _DATABASE_SECTION,
)
from .azure_cis._base import (
    _DEFENDER_SECTION as _DEFENDER_SECTION,
)
from .azure_cis._base import (
    _IAM_SECTION as _IAM_SECTION,
)
from .azure_cis._base import (
    _KEYVAULT_SECTION as _KEYVAULT_SECTION,
)
from .azure_cis._base import (
    _LOGGING_SECTION as _LOGGING_SECTION,
)
from .azure_cis._base import (
    _NETWORK_SECTION as _NETWORK_SECTION,
)
from .azure_cis._base import (
    _STORAGE_SECTION as _STORAGE_SECTION,
)
from .azure_cis._base import (
    _VM_SECTION as _VM_SECTION,
)
from .azure_cis._base import (
    AzureCISReport as AzureCISReport,
)
from .azure_cis._base import (
    _ca_client_app_types as _ca_client_app_types,
)
from .azure_cis._base import (
    _ca_conditions as _ca_conditions,
)
from .azure_cis._base import (
    _ca_enabled as _ca_enabled,
)
from .azure_cis._base import (
    _ca_grant_controls as _ca_grant_controls,
)
from .azure_cis._base import (
    _ca_included_apps as _ca_included_apps,
)
from .azure_cis._base import (
    _ca_included_roles as _ca_included_roles,
)
from .azure_cis._base import (
    _ca_included_users as _ca_included_users,
)
from .azure_cis._base import (
    _ca_sign_in_risk_levels as _ca_sign_in_risk_levels,
)
from .azure_cis._base import (
    _ca_state as _ca_state,
)
from .azure_cis._base import (
    _enum_text as _enum_text,
)
from .azure_cis._base import (
    _mark_unevaluable as _mark_unevaluable,
)
from .azure_cis._base import (
    _pass_or_no_data as _pass_or_no_data,
)
from .azure_cis._base import (
    _resolve_without_conditional_access as _resolve_without_conditional_access,
)
from .azure_cis._base import (
    logger as logger,
)
from .azure_cis.appservice import (
    _check_9_1 as _check_9_1,
)
from .azure_cis.appservice import (
    _check_9_2 as _check_9_2,
)
from .azure_cis.appservice import (
    _check_9_3 as _check_9_3,
)
from .azure_cis.appservice import (
    _check_9_4 as _check_9_4,
)
from .azure_cis.appservice import (
    _check_9_5 as _check_9_5,
)
from .azure_cis.appservice import (
    _check_9_6 as _check_9_6,
)
from .azure_cis.database_oss import (
    _check_4_2_2 as _check_4_2_2,
)
from .azure_cis.database_oss import (
    _check_4_2_3 as _check_4_2_3,
)
from .azure_cis.database_oss import (
    _check_4_3_1 as _check_4_3_1,
)
from .azure_cis.database_oss import (
    _check_4_3_2 as _check_4_3_2,
)
from .azure_cis.database_oss import (
    _check_4_3_3 as _check_4_3_3,
)
from .azure_cis.database_oss import (
    _check_4_3_4 as _check_4_3_4,
)
from .azure_cis.database_oss import (
    _check_4_3_5 as _check_4_3_5,
)
from .azure_cis.database_sql import (
    _check_4_1_1 as _check_4_1_1,
)
from .azure_cis.database_sql import (
    _check_4_1_2 as _check_4_1_2,
)
from .azure_cis.database_sql import (
    _check_4_1_3 as _check_4_1_3,
)
from .azure_cis.database_sql import (
    _check_4_1_4 as _check_4_1_4,
)
from .azure_cis.database_sql import (
    _check_4_1_5 as _check_4_1_5,
)
from .azure_cis.database_sql import (
    _check_4_1_6 as _check_4_1_6,
)
from .azure_cis.database_sql import (
    _check_4_2_1 as _check_4_2_1,
)
from .azure_cis.defender import (
    _check_2_1 as _check_2_1,
)
from .azure_cis.defender import (
    _check_2_2 as _check_2_2,
)
from .azure_cis.defender import (
    _check_2_3 as _check_2_3,
)
from .azure_cis.defender import (
    _check_2_4 as _check_2_4,
)
from .azure_cis.defender import (
    _check_2_5 as _check_2_5,
)
from .azure_cis.defender import (
    _check_2_6 as _check_2_6,
)
from .azure_cis.defender import (
    _check_2_7 as _check_2_7,
)
from .azure_cis.defender import (
    _check_2_8 as _check_2_8,
)
from .azure_cis.defender import (
    _check_2_9 as _check_2_9,
)
from .azure_cis.defender import (
    _check_2_10 as _check_2_10,
)
from .azure_cis.defender import (
    _check_2_11 as _check_2_11,
)
from .azure_cis.defender import (
    _check_2_12 as _check_2_12,
)
from .azure_cis.defender import (
    _check_2_13 as _check_2_13,
)
from .azure_cis.iam import (
    _check_1_1 as _check_1_1,
)
from .azure_cis.iam import (
    _check_1_2 as _check_1_2,
)
from .azure_cis.iam import (
    _check_1_3 as _check_1_3,
)
from .azure_cis.iam import (
    _check_1_4 as _check_1_4,
)
from .azure_cis.iam import (
    _check_1_5 as _check_1_5,
)
from .azure_cis.iam import (
    _check_1_6 as _check_1_6,
)
from .azure_cis.iam import (
    _check_1_7 as _check_1_7,
)
from .azure_cis.iam import (
    _check_1_8 as _check_1_8,
)
from .azure_cis.iam import (
    _check_1_9 as _check_1_9,
)
from .azure_cis.iam import (
    _check_1_10 as _check_1_10,
)
from .azure_cis.iam import (
    _guest_scoped_access_reviews as _guest_scoped_access_reviews,
)
from .azure_cis.iam_directory import (
    _check_1_11 as _check_1_11,
)
from .azure_cis.iam_directory import (
    _check_1_12 as _check_1_12,
)
from .azure_cis.iam_directory import (
    _check_1_13 as _check_1_13,
)
from .azure_cis.iam_directory import (
    _check_1_14 as _check_1_14,
)
from .azure_cis.iam_directory import (
    _check_1_15 as _check_1_15,
)
from .azure_cis.iam_directory import (
    _check_1_16 as _check_1_16,
)
from .azure_cis.iam_directory import (
    _check_1_17 as _check_1_17,
)
from .azure_cis.iam_directory import (
    _check_1_18 as _check_1_18,
)
from .azure_cis.iam_directory import (
    _check_1_19 as _check_1_19,
)
from .azure_cis.iam_directory import (
    _check_1_20 as _check_1_20,
)
from .azure_cis.iam_directory import (
    _check_1_21 as _check_1_21,
)
from .azure_cis.iam_directory import (
    _check_1_22 as _check_1_22,
)
from .azure_cis.keyvault import (
    _check_8_1 as _check_8_1,
)
from .azure_cis.keyvault import (
    _check_8_2 as _check_8_2,
)
from .azure_cis.keyvault import (
    _check_8_3 as _check_8_3,
)
from .azure_cis.keyvault import (
    _check_8_4 as _check_8_4,
)
from .azure_cis.keyvault import (
    _check_8_5 as _check_8_5,
)
from .azure_cis.keyvault import (
    _check_8_6 as _check_8_6,
)
from .azure_cis.keyvault import (
    _check_8_7 as _check_8_7,
)
from .azure_cis.logging_checks import (
    _check_5_1_2 as _check_5_1_2,
)
from .azure_cis.logging_checks import (
    _check_5_1_3 as _check_5_1_3,
)
from .azure_cis.logging_checks import (
    _check_5_1_4 as _check_5_1_4,
)
from .azure_cis.logging_checks import (
    _check_5_1_5 as _check_5_1_5,
)
from .azure_cis.logging_checks import (
    _check_5_1_6 as _check_5_1_6,
)
from .azure_cis.logging_checks import (
    _check_5_2_1 as _check_5_2_1,
)
from .azure_cis.logging_checks import (
    _check_5_2_2 as _check_5_2_2,
)
from .azure_cis.logging_checks import (
    _check_5_2_3 as _check_5_2_3,
)
from .azure_cis.logging_checks import (
    _check_activity_log_alert as _check_activity_log_alert,
)
from .azure_cis.networking import (
    _check_6_1 as _check_6_1,
)
from .azure_cis.networking import (
    _check_6_2 as _check_6_2,
)
from .azure_cis.networking import (
    _check_6_3 as _check_6_3,
)
from .azure_cis.networking import (
    _check_6_4 as _check_6_4,
)
from .azure_cis.networking import (
    _check_6_5 as _check_6_5,
)
from .azure_cis.networking import (
    _check_6_6 as _check_6_6,
)
from .azure_cis.networking import (
    _is_internet_exposed as _is_internet_exposed,
)
from .azure_cis.storage import (
    _check_3_1 as _check_3_1,
)
from .azure_cis.storage import (
    _check_3_3 as _check_3_3,
)
from .azure_cis.storage import (
    _check_3_4 as _check_3_4,
)
from .azure_cis.storage import (
    _check_3_5 as _check_3_5,
)
from .azure_cis.storage import (
    _check_3_6 as _check_3_6,
)
from .azure_cis.storage import (
    _check_3_7 as _check_3_7,
)
from .azure_cis.storage import (
    _check_3_8 as _check_3_8,
)
from .azure_cis.storage import (
    _check_3_9 as _check_3_9,
)
from .azure_cis.storage import (
    _check_3_10 as _check_3_10,
)
from .azure_cis.storage import (
    _check_3_11 as _check_3_11,
)
from .azure_cis.storage import (
    _check_3_12 as _check_3_12,
)
from .azure_cis.virtual_machines import (
    _check_7_1 as _check_7_1,
)
from .azure_cis.virtual_machines import (
    _check_7_2 as _check_7_2,
)
from .azure_cis.virtual_machines import (
    _check_7_3 as _check_7_3,
)
from .azure_cis.virtual_machines import (
    _check_7_4 as _check_7_4,
)
from .azure_cis.virtual_machines import (
    _check_7_5 as _check_7_5,
)
from .azure_cis.virtual_machines import (
    _check_7_6 as _check_7_6,
)
from .base import CloudDiscoveryError

# ---------------------------------------------------------------------------
# CIS 5.1.1 — subscription diagnostic settings (patch seam kept on this module)
# ---------------------------------------------------------------------------


_SUBSCRIPTION_DIAGNOSTIC_SETTINGS_API_VERSION = "2021-05-01-preview"


def _list_subscription_diagnostic_settings(credential: Any, subscription_id: str) -> list[dict[str, Any]]:
    """List subscription (Activity Log) diagnostic settings via read-only ARM.

    azure-mgmt-monitor 7.x targets only the latest API surface and no longer
    ships the diagnostic-settings operation groups, so this calls the
    documented ``Subscription Diagnostic Settings - List`` endpoint directly
    with the credential's own bearer token. Raises on any failure; the caller
    turns that into an ERROR result.
    """
    import json
    import urllib.parse
    import urllib.request

    token = credential.get_token("https://management.azure.com/.default").token
    sub = urllib.parse.quote(subscription_id, safe="")
    url = (
        f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings"
        f"?api-version={_SUBSCRIPTION_DIAGNOSTIC_SETTINGS_API_VERSION}"
    )
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})  # noqa: S310 — fixed https ARM endpoint
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310  # nosec B310 — fixed https ARM endpoint
        payload = json.loads(response.read().decode("utf-8"))
    value = payload.get("value") if isinstance(payload, dict) else None
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _check_5_1_1(monitor_client: Any, subscription_id: str, *, credential: Any = None) -> CISCheckResult:
    """CIS 5.1.1 — Ensure a Diagnostic Setting exists for the Activity Log."""
    result = CISCheckResult(
        check_id="5.1.1",
        title="Diagnostic setting captures Activity Log",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Create a Diagnostic Setting for the subscription Activity Log to export"
            " to a Log Analytics workspace, storage account, or Event Hub."
        ),
        cis_section=_LOGGING_SECTION,
    )
    try:
        legacy_operations = getattr(monitor_client, "diagnostic_settings", None)
        if legacy_operations is not None:
            # azure-mgmt-monitor < 7 still exposes the operation group.
            settings = list(legacy_operations.list(f"/subscriptions/{subscription_id}"))
        elif credential is not None:
            settings = _list_subscription_diagnostic_settings(credential, subscription_id)
        else:
            raise CloudDiscoveryError("No diagnostic-settings API is available on this Azure Monitor client.")

        if settings:
            result.status = CheckStatus.PASS
            result.evidence = f"Found {len(settings)} diagnostic setting(s) on the subscription."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No diagnostic settings found for the subscription Activity Log. Audit events are not being exported."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list diagnostic settings: {exc}"
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    subscription_id: str | None = None,
    checks: list[str] | None = None,
    credential: Any = None,
) -> AzureCISReport:
    """Run CIS Azure Security Benchmark v3.0 checks.

    Args:
        subscription_id: Azure subscription ID. Falls back to
            AZURE_SUBSCRIPTION_ID env var.
        checks: Optional list of check IDs to run (e.g. ['1.1', '6.1']).
            Runs all checks if omitted.
        credential: Optional Azure credential threaded into every check's
            management client. When ``None`` a ``DefaultAzureCredential`` is
            constructed (the prior behaviour). Passing a shared credential lets
            the multi-subscription fan-out resolve auth once and reuse it.

    Returns:
        AzureCISReport with pass/fail results for each check.

    Raises:
        CloudDiscoveryError: if azure-identity or azure-mgmt-* are not installed.
    """
    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not resolved_sub:
        raise CloudDiscoveryError("Azure subscription ID required. Set AZURE_SUBSCRIPTION_ID env var or pass subscription_id.")

    # azure-identity is only needed to build the default credential; a
    # caller-supplied credential (including the fail-closed dead-credential
    # path) must not require the optional SDK to be installed.
    if credential is None:
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise CloudDiscoveryError("azure-identity is required for Azure CIS benchmark. Install with: pip install 'agent-bom[azure]'")
        credential = DefaultAzureCredential()
    report = AzureCISReport(subscription_id=resolved_sub)

    # Build client map (lazy — only import what's needed)
    def _auth_client() -> Any:
        from azure.mgmt.authorization import AuthorizationManagementClient

        return AuthorizationManagementClient(credential, resolved_sub)

    def _storage_client() -> Any:
        from azure.mgmt.storage import StorageManagementClient

        return StorageManagementClient(credential, resolved_sub)

    def _monitor_client() -> Any:
        from azure.mgmt.monitor import MonitorManagementClient

        return MonitorManagementClient(credential, resolved_sub)

    def _network_client() -> Any:
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(credential, resolved_sub)

    def _security_client() -> Any:
        from azure.mgmt.security import SecurityCenter

        return SecurityCenter(credential, resolved_sub)

    def _sql_client() -> Any:
        from azure.mgmt.sql import SqlManagementClient

        return SqlManagementClient(credential, resolved_sub)

    def _compute_client() -> Any:
        from azure.mgmt.compute import ComputeManagementClient

        return ComputeManagementClient(credential, resolved_sub)

    def _kv_client() -> Any:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        return KeyVaultManagementClient(credential, resolved_sub)

    def _mysql_client() -> Any:
        from azure.mgmt.rdbms.mysql import MySQLManagementClient

        return MySQLManagementClient(credential, resolved_sub)

    def _postgresql_client() -> Any:
        from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient

        return PostgreSQLManagementClient(credential, resolved_sub)

    def _webapp_client() -> Any:
        from azure.mgmt.web import WebSiteManagementClient

        return WebSiteManagementClient(credential, resolved_sub)

    # Microsoft Graph reads the Entra directory state (Conditional Access, the
    # tenant authorization policy, security defaults, access reviews) that the ARM
    # management APIs do not expose. Built once and reused across the 1.x identity
    # controls; the credential caches its token internally.
    _graph_holder: dict[str, Any] = {}

    def _graph_client() -> Any:
        client = _graph_holder.get("client")
        if client is None:
            from .azure_graph import AzureGraphClient

            client = AzureGraphClient(credential)
            _graph_holder["client"] = client
        return client

    all_checks: list[tuple[str, Any]] = [
        # Section 1 — Identity and Access Management
        ("1.1", lambda: _check_1_1(_auth_client(), resolved_sub)),
        ("1.2", lambda: _check_1_2(_auth_client(), resolved_sub)),
        ("1.3", lambda: _check_1_3(_graph_client())),
        ("1.4", lambda: _check_1_4(_graph_client())),
        ("1.5", lambda: _check_1_5(_auth_client(), resolved_sub)),
        ("1.6", lambda: _check_1_6(_graph_client())),
        ("1.7", lambda: _check_1_7(_auth_client(), resolved_sub)),
        ("1.8", lambda: _check_1_8(_graph_client())),
        ("1.9", lambda: _check_1_9(_graph_client())),
        ("1.10", lambda: _check_1_10()),
        ("1.11", lambda: _check_1_11(_graph_client())),
        ("1.12", lambda: _check_1_12(_graph_client())),
        ("1.13", lambda: _check_1_13(_graph_client())),
        ("1.14", lambda: _check_1_14(_graph_client())),
        ("1.15", lambda: _check_1_15(_auth_client(), resolved_sub)),
        ("1.16", lambda: _check_1_16()),
        ("1.17", lambda: _check_1_17()),
        ("1.18", lambda: _check_1_18(_graph_client())),
        ("1.19", lambda: _check_1_19()),
        ("1.20", lambda: _check_1_20()),
        ("1.21", lambda: _check_1_21(_graph_client())),
        ("1.22", lambda: _check_1_22(_graph_client())),
        # Section 2 — Microsoft Defender for Cloud
        ("2.1", lambda: _check_2_1(_security_client(), resolved_sub)),
        ("2.2", lambda: _check_2_2(_security_client(), resolved_sub)),
        ("2.3", lambda: _check_2_3(_security_client(), resolved_sub)),
        ("2.4", lambda: _check_2_4(_security_client(), resolved_sub)),
        ("2.5", lambda: _check_2_5(_security_client(), resolved_sub)),
        ("2.6", lambda: _check_2_6(_security_client(), resolved_sub)),
        ("2.7", lambda: _check_2_7(_security_client(), resolved_sub)),
        ("2.8", lambda: _check_2_8(_security_client(), resolved_sub)),
        ("2.9", lambda: _check_2_9(_security_client(), resolved_sub)),
        ("2.10", lambda: _check_2_10(_security_client(), resolved_sub)),
        ("2.11", lambda: _check_2_11(_security_client(), resolved_sub)),
        ("2.12", lambda: _check_2_12(_security_client(), resolved_sub)),
        ("2.13", lambda: _check_2_13(_security_client(), resolved_sub)),
        # Section 3 — Storage Accounts
        ("3.1", lambda: _check_3_1(_storage_client())),
        ("3.3", lambda: _check_3_3(_storage_client())),
        ("3.4", lambda: _check_3_4(_storage_client())),
        ("3.5", lambda: _check_3_5(_storage_client())),
        ("3.6", lambda: _check_3_6(_storage_client())),
        ("3.7", lambda: _check_3_7(_storage_client())),
        ("3.8", lambda: _check_3_8(_storage_client())),
        ("3.9", lambda: _check_3_9(_storage_client())),
        ("3.10", lambda: _check_3_10(_storage_client())),
        ("3.11", lambda: _check_3_11(_storage_client())),
        ("3.12", lambda: _check_3_12(_storage_client())),
        # Section 4 — Database Services
        ("4.1.1", lambda: _check_4_1_1(_sql_client())),
        ("4.1.2", lambda: _check_4_1_2(_sql_client())),
        ("4.1.3", lambda: _check_4_1_3(_sql_client())),
        ("4.1.4", lambda: _check_4_1_4(_sql_client())),
        ("4.1.5", lambda: _check_4_1_5(_sql_client())),
        ("4.1.6", lambda: _check_4_1_6(_sql_client())),
        ("4.2.1", lambda: _check_4_2_1(_sql_client())),
        ("4.2.2", lambda: _check_4_2_2(_mysql_client())),
        ("4.2.3", lambda: _check_4_2_3(_mysql_client())),
        ("4.3.1", lambda: _check_4_3_1(_postgresql_client())),
        ("4.3.2", lambda: _check_4_3_2(_postgresql_client())),
        ("4.3.3", lambda: _check_4_3_3(_postgresql_client())),
        ("4.3.4", lambda: _check_4_3_4(_postgresql_client())),
        ("4.3.5", lambda: _check_4_3_5(_postgresql_client())),
        # Section 5 — Logging and Monitoring
        ("5.1.1", lambda: _check_5_1_1(_monitor_client(), resolved_sub, credential=credential)),
        ("5.1.2", lambda: _check_5_1_2(_monitor_client(), resolved_sub)),
        ("5.1.3", lambda: _check_5_1_3(_monitor_client(), resolved_sub)),
        ("5.1.4", lambda: _check_5_1_4(_monitor_client(), resolved_sub)),
        ("5.1.5", lambda: _check_5_1_5(_monitor_client(), resolved_sub)),
        ("5.1.6", lambda: _check_5_1_6(_monitor_client(), resolved_sub)),
        ("5.2.1", lambda: _check_5_2_1(_postgresql_client())),
        ("5.2.2", lambda: _check_5_2_2(_postgresql_client())),
        ("5.2.3", lambda: _check_5_2_3(_postgresql_client())),
        # Section 6 — Networking
        ("6.1", lambda: _check_6_1(_network_client())),
        ("6.2", lambda: _check_6_2(_network_client())),
        ("6.3", lambda: _check_6_3(_network_client())),
        ("6.4", lambda: _check_6_4(_network_client())),
        ("6.5", lambda: _check_6_5(_network_client())),
        ("6.6", lambda: _check_6_6(_network_client())),
        # Section 7 — Virtual Machines
        ("7.1", lambda: _check_7_1(_compute_client())),
        ("7.2", lambda: _check_7_2(_compute_client())),
        ("7.3", lambda: _check_7_3(_compute_client())),
        ("7.4", lambda: _check_7_4(_compute_client())),
        ("7.5", lambda: _check_7_5(_compute_client())),
        ("7.6", lambda: _check_7_6(_compute_client())),
        # Section 8 — Key Vault
        ("8.1", lambda: _check_8_1(_kv_client(), resolved_sub)),
        ("8.2", lambda: _check_8_2(_kv_client(), resolved_sub)),
        ("8.3", lambda: _check_8_3(_kv_client(), resolved_sub)),
        ("8.4", lambda: _check_8_4(_kv_client(), resolved_sub)),
        ("8.5", lambda: _check_8_5(_kv_client(), resolved_sub)),
        ("8.6", lambda: _check_8_6(_kv_client(), resolved_sub)),
        ("8.7", lambda: _check_8_7(_kv_client(), resolved_sub)),
        # Section 9 — App Service
        ("9.1", lambda: _check_9_1(_webapp_client())),
        ("9.2", lambda: _check_9_2(_webapp_client())),
        ("9.3", lambda: _check_9_3(_webapp_client())),
        ("9.4", lambda: _check_9_4(_webapp_client())),
        ("9.5", lambda: _check_9_5(_webapp_client())),
        ("9.6", lambda: _check_9_6(_webapp_client())),
    ]

    for check_id, check_fn in all_checks:
        if checks and check_id not in checks:
            continue
        try:
            report.checks.append(check_fn())
        except Exception as exc:
            logger.warning("Azure CIS check %s failed with exception: %s", check_id, sanitize_text(exc))
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=f"Check {check_id}",
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=str(exc),
                )
            )

    # Structured remediation per #665.
    from agent_bom.cloud.cis_remediation import attach_all

    attach_all(report, cloud="azure")

    return report


# Bounded concurrency for the multi-subscription fan-out — mirrors the Azure
# inventory fan-out's thread pool so a tenant-wide CIS run collapses the
# per-subscription latencies instead of summing them.
_MAX_CIS_FANOUT_WORKERS = 8


def run_all_subscription_benchmarks(
    checks: list[str] | None = None,
    credential: Any = None,
) -> AzureCISReport:
    """Run the CIS Azure benchmark for EVERY subscription in the tenant.

    The CIS counterpart of :func:`agent_bom.cloud.azure_inventory.discover_all_subscription_inventories`:
    it reuses the exact same subscription enumeration
    (:func:`agent_bom.cloud.azure_inventory.enumerate_subscription_ids`, which
    walks the management-group tree) so the benchmark covers the identical
    estate the inventory fan-out does. Each subscription is benchmarked
    concurrently (bounded thread pool) and the per-subscription results are
    aggregated into one :class:`AzureCISReport` with every check tagged by its
    ``subscription_id``.

    Read-only and partial-permission tolerant: a subscription the credential
    cannot read is skipped with a warning rather than failing the whole run.

    Raises:
        CloudDiscoveryError: if azure-identity is not installed.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from agent_bom.cloud import azure_inventory

    if credential is None:
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise CloudDiscoveryError("azure-identity is required for Azure CIS benchmark. Install with: pip install 'agent-bom[azure]'")
        credential = DefaultAzureCredential()

    sub_ids, warnings = azure_inventory.enumerate_subscription_ids(credential)
    if not sub_ids:
        raise CloudDiscoveryError(
            "No Azure subscriptions resolved for the multi-subscription CIS benchmark. "
            "Grant Management Group Reader or set AZURE_SUBSCRIPTION_ID."
        )

    aggregate = AzureCISReport(subscription_id=", ".join(sub_ids))
    aggregate.warnings.extend(warnings)

    def _run_one(sub_id: str) -> tuple[str, AzureCISReport]:
        return sub_id, run_benchmark(subscription_id=sub_id, checks=checks, credential=credential)

    # Deterministic aggregation: collect per-subscription reports keyed by id,
    # then merge in the enumeration order so output is stable across runs.
    reports: dict[str, AzureCISReport] = {}
    with ThreadPoolExecutor(max_workers=min(_MAX_CIS_FANOUT_WORKERS, len(sub_ids))) as executor:
        future_to_sub = {executor.submit(_run_one, sub_id): sub_id for sub_id in sub_ids}
        for future in as_completed(future_to_sub):
            sub_id = future_to_sub[future]
            try:
                _sid, sub_report = future.result()
                reports[sub_id] = sub_report
            except Exception as exc:  # noqa: BLE001 — one unreadable subscription must not sink the rest
                from .normalization import sanitize_discovery_warning

                aggregate.warnings.append(f"Subscription {sub_id} skipped: {sanitize_discovery_warning(exc)}")

    for sub_id in sub_ids:
        merged = reports.get(sub_id)
        if merged is None:
            continue
        aggregate.subscriptions_scanned.append(sub_id)
        for check in merged.checks:
            check.account_id = sub_id
            aggregate.checks.append(check)
        aggregate.warnings.extend(merged.warnings)

    return aggregate
