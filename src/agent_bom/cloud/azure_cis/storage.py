"""CIS Azure section 3 — Storage account checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage
from ..aws_inventory import is_access_denied_error
from ._base import (
    _STORAGE_SECTION,
    _enum_text,
    _pass_or_no_data,
    logger,
)


def _check_3_1(storage_client: Any) -> CISCheckResult:
    """CIS 3.1 — Ensure 'Secure Transfer Required' is enabled on all Storage Accounts."""
    result = CISCheckResult(
        check_id="3.1",
        title="Secure transfer required on storage accounts",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'Secure transfer required' on all storage accounts to enforce HTTPS-only access.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            props = getattr(acct, "enable_https_traffic_only", None)
            if props is False:
                failing.append(acct.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without secure transfer: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) have secure transfer enabled."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_7(storage_client: Any) -> CISCheckResult:
    """CIS 3.7 — Ensure public access is disabled on all Storage Account blob containers."""
    result = CISCheckResult(
        check_id="3.7",
        title="Blob containers set to private access",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Disable public blob access at the storage account level and audit all containers.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            allow_blob_public = getattr(acct, "allow_blob_public_access", None)
            if allow_blob_public is True:
                failing.append(acct.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts with public blob access allowed: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) have public blob access disabled."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account blob access settings: {exc}"
    return result


def _check_3_10(storage_client: Any) -> CISCheckResult:
    """CIS 3.10 — Ensure soft delete is enabled for Azure Storage."""
    result = CISCheckResult(
        check_id="3.10",
        title="Soft delete enabled for Azure Storage",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable blob soft delete on all storage accounts to protect against accidental deletion.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for acct in accounts:
            acct_name = acct.name or "unknown"
            # Extract resource group from account ID
            acct_id = getattr(acct, "id", "") or ""
            parts = acct_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                logger.debug("Could not extract resource group from storage account %s", acct_name)
                continue

            try:
                blob_props = storage_client.blob_services.get_service_properties(resource_group, acct_name)
                inspected += 1
                retention = getattr(blob_props, "delete_retention_policy", None)
                enabled = getattr(retention, "enabled", False) if retention else False
                if not enabled:
                    failing.append(acct_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(acct_name)
                logger.debug("Could not check soft delete for %s: %s", acct_name, sanitize_text(exc))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without blob soft delete: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Storage/storageAccounts/blobServices/read",
                resource_kind="storage account",
                pass_evidence=f"All {len(accounts)} storage account(s) have blob soft delete enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account soft delete settings: {exc}"
    return result


def _check_3_3(storage_client: Any) -> CISCheckResult:
    """CIS 3.3 — Ensure storage for critical data is encrypted with Customer Managed Key."""
    result = CISCheckResult(
        check_id="3.3",
        title="Critical-data storage encrypted with customer-managed key",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure Customer Managed Keys (CMK) for storage accounts containing critical data.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        non_cmk = []
        for acct in accounts:
            encryption = getattr(acct, "encryption", None)
            key_source = getattr(encryption, "key_source", "") if encryption else ""
            key_source_str = _enum_text(key_source)
            if key_source_str.lower() != "microsoft.keyvault":
                non_cmk.append(acct.name)
        if non_cmk:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts not using CMK encryption: {', '.join(non_cmk)}"
            result.resource_ids = non_cmk
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) use Customer Managed Key encryption."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account encryption settings: {exc}"
    return result


def _check_3_4(storage_client: Any) -> CISCheckResult:
    """CIS 3.4 — Ensure storage logging is enabled for Queue service."""
    result = CISCheckResult(
        check_id="3.4",
        title="Storage logging enabled for Queue service",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Storage Analytics logging for Queue service read, write, and delete operations.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        result.status = CheckStatus.NO_DATA
        result.evidence = (
            f"Not evaluated — Queue service logging is a per-account data-plane setting this read-only "
            f"management-plane scan does not read ({len(accounts)} storage account(s) found). Verify via "
            "Storage Account > Diagnostics settings (classic) or Azure Monitor; this is NOT treated as passed."
        )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_5(storage_client: Any) -> CISCheckResult:
    """CIS 3.5 — Ensure storage logging is enabled for Table service."""
    result = CISCheckResult(
        check_id="3.5",
        title="Storage logging enabled for Table service",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Storage Analytics logging for Table service read, write, and delete operations.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        result.status = CheckStatus.NO_DATA
        result.evidence = (
            f"Not evaluated — Table service logging is a per-account data-plane setting this read-only "
            f"management-plane scan does not read ({len(accounts)} storage account(s) found). Verify via "
            "Storage Account > Diagnostics settings (classic) or Azure Monitor; this is NOT treated as passed."
        )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_6(storage_client: Any) -> CISCheckResult:
    """CIS 3.6 — Ensure storage logging is enabled for Blob service."""
    result = CISCheckResult(
        check_id="3.6",
        title="Storage logging enabled for Blob service",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Storage Analytics logging for Blob service read, write, and delete operations.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        result.status = CheckStatus.NO_DATA
        result.evidence = (
            f"Not evaluated — Blob service logging is a per-account data-plane setting this read-only "
            f"management-plane scan does not read ({len(accounts)} storage account(s) found). Verify via "
            "Storage Account > Diagnostics settings (classic) or Azure Monitor; this is NOT treated as passed."
        )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_8(storage_client: Any) -> CISCheckResult:
    """CIS 3.8 — Ensure default network access rule for Storage Accounts is set to Deny."""
    result = CISCheckResult(
        check_id="3.8",
        title="Default storage network access rule set to Deny",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the default network access rule to 'Deny' on all storage accounts.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            network_rule_set = getattr(acct, "network_rule_set", None)
            default_action = getattr(network_rule_set, "default_action", None) if network_rule_set else None
            default_action_str = _enum_text(default_action)
            if default_action_str.lower() != "deny":
                failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts with default network access Allow: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) have default network access set to Deny."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account network rules: {exc}"
    return result


def _check_3_9(storage_client: Any) -> CISCheckResult:
    """CIS 3.9 — Ensure 'Allow Azure services on the trusted services list' is enabled."""
    result = CISCheckResult(
        check_id="3.9",
        title="Trusted Azure services allowed to access storage account",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable 'Allow trusted Microsoft services to access this storage account' in the storage account firewall settings.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            network_rule_set = getattr(acct, "network_rule_set", None)
            if network_rule_set:
                bypass_str = _enum_text(getattr(network_rule_set, "bypass", None))
                if "azureservices" not in {part.strip().lower() for part in bypass_str.split(",")}:
                    failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without trusted Azure services bypass: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) allow trusted Azure services."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account trusted services settings: {exc}"
    return result


def _check_3_11(storage_client: Any) -> CISCheckResult:
    """CIS 3.11 — Ensure private endpoints are used to access Storage Accounts."""
    result = CISCheckResult(
        check_id="3.11",
        title="Private endpoints used for storage accounts",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure private endpoints for all storage accounts to restrict network access to approved virtual networks.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            pe_conns = getattr(acct, "private_endpoint_connections", None) or []
            if not pe_conns:
                failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without private endpoints: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) have private endpoints configured."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account private endpoints: {exc}"
    return result


def _check_3_12(storage_client: Any) -> CISCheckResult:
    """CIS 3.12 — Ensure infrastructure encryption for Storage Accounts is enabled."""
    result = CISCheckResult(
        check_id="3.12",
        title="Infrastructure encryption enabled on storage accounts",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable infrastructure encryption (double encryption) for storage accounts containing sensitive data.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            encryption = getattr(acct, "encryption", None)
            infra_encryption = getattr(encryption, "require_infrastructure_encryption", False) if encryption else False
            if not infra_encryption:
                failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without infrastructure encryption: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(
                result, len(accounts), "storage account", f"All {len(accounts)} storage account(s) have infrastructure encryption enabled."
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account infrastructure encryption: {exc}"
    return result
