"""CIS Azure section 8 — Key Vault checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage
from ..aws_inventory import is_access_denied_error
from ._base import (
    _KEYVAULT_SECTION,
    logger,
)


def _check_8_1(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.1 — Ensure expiration date is set on all Key Vault keys."""
    result = CISCheckResult(
        check_id="8.1",
        title="Expiration date set on Key Vault keys",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all Key Vault keys to enforce key rotation.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_keys: list[str] = []
        readable = 0
        denied: list[str] = []

        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient

                key_client = KeyClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for key_prop in key_client.list_properties_of_keys():
                    exp = getattr(key_prop, "expires_on", None)
                    if exp is None:
                        failing_keys.append(f"{vault_name}/{key_prop.name}")
                readable += 1
            except Exception as exc:
                # Data-plane read denied (Reader has no vault data-plane) — this
                # vault is UNREADABLE, not compliant. Never let it fall through
                # to PASS: a denied vault must not read as "keys have expiration".
                denied.append(vault_name)
                logger.debug("Could not enumerate keys in vault %s: %s", vault_name, sanitize_text(exc))

        if failing_keys:
            result.status = CheckStatus.FAIL
            result.evidence = f"Keys without expiration: {', '.join(failing_keys[:10])}"
            result.resource_ids = failing_keys
        elif vaults and readable == 0:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Could not read keys in any of {len(vaults)} vault(s) — data-plane access denied. "
                "Grant the scanner 'Key Vault Reader' (RBAC vaults) or a List access policy "
                "(access-policy vaults) to evaluate CIS 8.1."
            )
        else:
            note = f" ({len(denied)} vault(s) skipped — data-plane access denied)" if denied else ""
            result.status = CheckStatus.PASS
            result.evidence = f"All keys across {readable} readable vault(s) have expiration dates set.{note}"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate Key Vault keys: {exc}"
    return result


def _check_8_2(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.2 — Ensure expiration date is set on all Key Vault secrets."""
    result = CISCheckResult(
        check_id="8.2",
        title="Expiration date set on Key Vault secrets",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all Key Vault secrets to enforce secret rotation.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_secrets: list[str] = []
        readable = 0
        denied: list[str] = []

        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient

                secret_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for secret_prop in secret_client.list_properties_of_secrets():
                    if getattr(secret_prop, "expires_on", None) is None:
                        failing_secrets.append(f"{vault_name}/{secret_prop.name}")
                readable += 1
            except Exception as exc:
                # Denied vault is UNREADABLE, not compliant — never fall through to PASS.
                denied.append(vault_name)
                logger.debug("Could not enumerate secrets in vault %s: %s", vault_name, sanitize_text(exc))

        if failing_secrets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Secrets without expiration: {', '.join(failing_secrets[:10])}"
            result.resource_ids = failing_secrets
        elif vaults and readable == 0:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Could not read secrets in any of {len(vaults)} vault(s) — data-plane access denied. "
                "Grant the scanner 'Key Vault Reader' (RBAC vaults) or a List access policy "
                "(access-policy vaults) to evaluate CIS 8.2."
            )
        else:
            note = f" ({len(denied)} vault(s) skipped — data-plane access denied)" if denied else ""
            result.status = CheckStatus.PASS
            result.evidence = f"All secrets across {readable} readable vault(s) have expiration dates set.{note}"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate Key Vault secrets: {exc}"
    return result


def _check_8_3(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.3 — Ensure Key Vault is recoverable (soft delete + purge protection)."""
    result = CISCheckResult(
        check_id="8.3",
        title="Key Vault recoverable (soft-delete and purge protection)",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable both soft-delete and purge protection on all Key Vaults.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                inspected += 1
                props = getattr(full_vault, "properties", None)
                soft_delete = getattr(props, "enable_soft_delete", False) if props else False
                purge_protection = getattr(props, "enable_purge_protection", False) if props else False
                if not soft_delete or not purge_protection:
                    missing = []
                    if not soft_delete:
                        missing.append("soft-delete")
                    if not purge_protection:
                        missing.append("purge-protection")
                    failing.append(f"{vault_name} (missing: {', '.join(missing)})")
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(vault_name)
                logger.debug("Could not check recoverability for vault %s: %s", vault_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Key Vaults without full recoverability: {', '.join(failing[:10])}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.KeyVault/vaults/read",
                resource_kind="Key Vault",
                pass_evidence="All Key Vault(s) have soft-delete and purge protection enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault recoverability: {exc}"
    return result


def _check_8_4(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.4 — Ensure key expiration date is set for all keys in RBAC Key Vaults."""
    result = CISCheckResult(
        check_id="8.4",
        title="Expiration date set on RBAC Key Vault keys",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all keys in Key Vaults using RBAC access model.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_keys: list[str] = []
        rbac_vault_count = 0
        readable = 0
        denied: list[str] = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                props = getattr(full_vault, "properties", None)
                rbac_enabled = getattr(props, "enable_rbac_authorization", False) if props else False
                if not rbac_enabled:
                    continue
                rbac_vault_count += 1
            except Exception:
                continue
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient

                key_client = KeyClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for key_prop in key_client.list_properties_of_keys():
                    if getattr(key_prop, "expires_on", None) is None:
                        failing_keys.append(f"{vault_name}/{key_prop.name}")
                readable += 1
            except Exception as exc:
                # Denied RBAC vault is UNREADABLE, not compliant — never PASS.
                denied.append(vault_name)
                logger.debug("Could not enumerate keys in RBAC vault %s: %s", vault_name, sanitize_text(exc))
        if failing_keys:
            result.status = CheckStatus.FAIL
            result.evidence = f"Keys without expiration in RBAC vaults: {', '.join(failing_keys[:10])}"
            result.resource_ids = failing_keys
        elif rbac_vault_count and readable == 0:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Could not read keys in any of {rbac_vault_count} RBAC vault(s) — data-plane access denied. "
                "Grant the scanner 'Key Vault Reader' to evaluate CIS 8.4."
            )
            result.resource_ids = denied
        else:
            note = f" ({len(denied)} vault(s) skipped — data-plane access denied)" if denied else ""
            result.status = CheckStatus.PASS
            result.evidence = f"All keys in {readable} readable RBAC vault(s) have expiration dates set.{note}"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault key expiration: {exc}"
    return result


def _check_8_5(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.5 — Ensure secret expiration date is set for all secrets in RBAC Key Vaults."""
    result = CISCheckResult(
        check_id="8.5",
        title="Expiration date set on RBAC Key Vault secrets",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all secrets in Key Vaults using RBAC access model.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_secrets: list[str] = []
        rbac_vault_count = 0
        readable = 0
        denied: list[str] = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                props = getattr(full_vault, "properties", None)
                rbac_enabled = getattr(props, "enable_rbac_authorization", False) if props else False
                if not rbac_enabled:
                    continue
                rbac_vault_count += 1
            except Exception:
                continue
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient

                secret_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for secret_prop in secret_client.list_properties_of_secrets():
                    if getattr(secret_prop, "expires_on", None) is None:
                        failing_secrets.append(f"{vault_name}/{secret_prop.name}")
                readable += 1
            except Exception as exc:
                # Denied RBAC vault is UNREADABLE, not compliant — never PASS.
                denied.append(vault_name)
                logger.debug("Could not enumerate secrets in RBAC vault %s: %s", vault_name, sanitize_text(exc))
        if failing_secrets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Secrets without expiration in RBAC vaults: {', '.join(failing_secrets[:10])}"
            result.resource_ids = failing_secrets
        elif rbac_vault_count and readable == 0:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Could not read secrets in any of {rbac_vault_count} RBAC vault(s) — data-plane access denied. "
                "Grant the scanner 'Key Vault Reader' to evaluate CIS 8.5."
            )
            result.resource_ids = denied
        else:
            note = f" ({len(denied)} vault(s) skipped — data-plane access denied)" if denied else ""
            result.status = CheckStatus.PASS
            result.evidence = f"All secrets in {readable} readable RBAC vault(s) have expiration dates set.{note}"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault secret expiration: {exc}"
    return result


def _check_8_6(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.6 — Ensure Key Vault secrets have content type set."""
    result = CISCheckResult(
        check_id="8.6",
        title="Key Vault secrets have a content type set",
        status=CheckStatus.ERROR,
        severity="low",
        recommendation="Set a content type on all Key Vault secrets to describe the secret's usage.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_secrets: list[str] = []
        readable = 0
        denied: list[str] = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient

                secret_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for secret_prop in secret_client.list_properties_of_secrets():
                    content_type = getattr(secret_prop, "content_type", None)
                    if not content_type:
                        failing_secrets.append(f"{vault_name}/{secret_prop.name}")
                readable += 1
            except Exception as exc:
                # Denied vault is UNREADABLE, not compliant — never PASS.
                denied.append(vault_name)
                logger.debug("Could not enumerate secrets in vault %s: %s", vault_name, sanitize_text(exc))
        if failing_secrets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Secrets without content type: {', '.join(failing_secrets[:10])}"
            result.resource_ids = failing_secrets
        elif vaults and readable == 0:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Could not read secrets in any of {len(vaults)} vault(s) — data-plane access denied. "
                "Grant the scanner 'Key Vault Reader' (RBAC vaults) or a List access policy "
                "(access-policy vaults) to evaluate CIS 8.6."
            )
            result.resource_ids = denied
        else:
            note = f" ({len(denied)} vault(s) skipped — data-plane access denied)" if denied else ""
            result.status = CheckStatus.PASS
            result.evidence = f"All secrets across {readable} readable vault(s) have content type set.{note}"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault secret content types: {exc}"
    return result


def _check_8_7(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.7 — Ensure private endpoints are used for Key Vault."""
    result = CISCheckResult(
        check_id="8.7",
        title="Private endpoints used for Key Vault",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure private endpoints for all Key Vaults to restrict network access.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                inspected += 1
                props = getattr(full_vault, "properties", None)
                pe_conns = getattr(props, "private_endpoint_connections", None) if props else None
                if not pe_conns:
                    failing.append(vault_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(vault_name)
                logger.debug("Could not check private endpoints for vault %s: %s", vault_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Key Vaults without private endpoints: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.KeyVault/vaults/read",
                resource_kind="Key Vault",
                pass_evidence="All Key Vault(s) have private endpoints configured.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault private endpoints: {exc}"
    return result
