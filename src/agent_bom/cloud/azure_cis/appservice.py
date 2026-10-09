"""CIS Azure section 9 — App Service checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage
from ..aws_inventory import is_access_denied_error
from ._base import (
    _APPSERVICE_SECTION,
    _enum_text,
    _pass_or_no_data,
    logger,
)


def _check_9_1(webapp_client: Any) -> CISCheckResult:
    """CIS 9.1 — Ensure App Service Authentication is set on."""
    result = CISCheckResult(
        check_id="9.1",
        title="App Service Authentication configured",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable App Service Authentication (EasyAuth) on all web apps.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for app in apps:
            app_name = app.name or "unknown"
            app_id = getattr(app, "id", "") or ""
            parts = app_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                auth_settings = webapp_client.web_apps.get_auth_settings(resource_group, app_name)
                inspected += 1
                enabled = getattr(auth_settings, "enabled", False)
                if not enabled:
                    failing.append(app_name)
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(app_name)
                logger.debug("Could not check auth settings for app %s: %s", app_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without authentication enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Web/sites/config/list (authsettings)",
                resource_kind="web app",
                pass_evidence=f"All {len(apps)} web app(s) have App Service Authentication enabled.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check App Service authentication settings: {exc}"
    return result


def _check_9_2(webapp_client: Any) -> CISCheckResult:
    """CIS 9.2 — Ensure web app redirects all HTTP traffic to HTTPS."""
    result = CISCheckResult(
        check_id="9.2",
        title="Web app redirects HTTP to HTTPS",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'HTTPS Only' on all web apps to redirect HTTP to HTTPS.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            https_only = getattr(app, "https_only", False)
            if not https_only:
                failing.append(app_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without HTTPS-only enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(apps), "web app", f"All {len(apps)} web app(s) have HTTPS-only enabled.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app HTTPS settings: {exc}"
    return result


def _check_9_3(webapp_client: Any) -> CISCheckResult:
    """CIS 9.3 — Ensure web app is using the latest TLS version."""
    result = CISCheckResult(
        check_id="9.3",
        title="Web app uses latest TLS version",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the minimum TLS version to 1.2 on all web apps.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for app in apps:
            app_name = app.name or "unknown"
            app_id = getattr(app, "id", "") or ""
            parts = app_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = webapp_client.web_apps.get_configuration(resource_group, app_name)
                inspected += 1
                min_tls = _enum_text(getattr(config, "min_tls_version", None))
                if not min_tls:
                    # An unreported minimum TLS version is not a pass — the app is
                    # not demonstrably enforcing TLS 1.2+, so flag it.
                    failing.append(f"{app_name} (TLS version not set)")
                elif "1.2" not in min_tls and "1.3" not in min_tls:
                    failing.append(f"{app_name} (TLS: {min_tls})")
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(app_name)
                logger.debug("Could not check TLS for app %s: %s", app_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps not using TLS 1.2+: {', '.join(failing[:10])}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Web/sites/config/read",
                resource_kind="web app",
                pass_evidence=f"All {len(apps)} web app(s) use TLS 1.2 or higher.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app TLS settings: {exc}"
    return result


def _check_9_4(webapp_client: Any) -> CISCheckResult:
    """CIS 9.4 — Ensure the web app has a Managed Identity."""
    result = CISCheckResult(
        check_id="9.4",
        title="Web app has a Managed Service Identity",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable a System-Assigned or User-Assigned Managed Identity on all web apps.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            identity = getattr(app, "identity", None)
            if identity is None:
                failing.append(app_name)
            else:
                identity_type = getattr(identity, "type", "") or ""
                if not identity_type or identity_type.lower() == "none":
                    failing.append(app_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without Managed Identity: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(apps), "web app", f"All {len(apps)} web app(s) have Managed Identity enabled.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app Managed Identity settings: {exc}"
    return result


def _check_9_5(webapp_client: Any) -> CISCheckResult:
    """CIS 9.5 — Ensure web app has client certificates (Incoming client certificates) enabled."""
    result = CISCheckResult(
        check_id="9.5",
        title="Web app requires incoming client certificates",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable client certificates on all web apps that require mutual TLS authentication.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            client_cert_enabled = getattr(app, "client_cert_enabled", False)
            if not client_cert_enabled:
                failing.append(app_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without client certificates enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(apps), "web app", f"All {len(apps)} web app(s) have client certificates enabled.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app client certificate settings: {exc}"
    return result


def _check_9_6(webapp_client: Any) -> CISCheckResult:
    """CIS 9.6 — Ensure FTP access is disabled for App Service."""
    result = CISCheckResult(
        check_id="9.6",
        title="FTP access disabled for App Service",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Disable FTP/FTPS access on all web apps. Use FTPS-only or disable FTP state entirely.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        inspected = 0
        denied: list[str] = []
        for app in apps:
            app_name = app.name or "unknown"
            app_id = getattr(app, "id", "") or ""
            parts = app_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = webapp_client.web_apps.get_configuration(resource_group, app_name)
                inspected += 1
                ftp_state = getattr(config, "ftp_state", "") or ""
                if ftp_state.lower() not in ("disabled", "ftpsonly"):
                    failing.append(f"{app_name} (FTP: {ftp_state})")
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(app_name)
                logger.debug("Could not check FTP state for app %s: %s", app_name, sanitize_text(exc))
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps with FTP enabled: {', '.join(failing[:10])}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            finalize_read_coverage(
                result,
                inspected=inspected,
                denied=denied,
                permission="Microsoft.Web/sites/config/read",
                resource_kind="web app",
                pass_evidence=f"All {len(apps)} web app(s) have FTP access disabled or FTPS-only.",
            )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check App Service FTP settings: {exc}"
    return result
