"""Shared model, section labels and evidence helpers for the CIS Azure benchmark."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agent_bom.security import sanitize_error

from ..aws_cis_benchmark import CheckStatus, CISCheckResult
from ..azure_graph import SECURITY_DEFAULTS_PATH, GraphError, GraphPermissionDeniedError

# Keep the historical logger name so log routing and filters are unchanged.
logger = logging.getLogger("agent_bom.cloud.azure_cis_benchmark")


@dataclass
class AzureCISReport:
    """Aggregated CIS Azure Security Benchmark results."""

    benchmark_version: str = "3.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    subscription_id: str = ""
    # Populated only by the multi-subscription fan-out: the subscriptions actually
    # evaluated and any per-subscription warnings (e.g. a subscription skipped
    # because the credential could not read it). Empty for a single-sub run.
    subscriptions_scanned: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def errored(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.ERROR)

    @property
    def not_applicable(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NOT_APPLICABLE)

    @property
    def no_data(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NO_DATA)

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.evaluated * 100) if self.evaluated else 0.0

    def to_dict(self) -> dict:
        from agent_bom.cloud.benchmark_manifests import benchmark_manifest
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "CIS Microsoft Azure Foundations",
            "benchmark_version": self.benchmark_version,
            "benchmark_manifest": benchmark_manifest("azure"),
            "subscription_id": self.subscription_id,
            "subscriptions_scanned": self.subscriptions_scanned,
            "warnings": self.warnings,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "not_applicable": self.not_applicable,
            "no_data": self.no_data,
            "evaluated": self.evaluated,
            "total": self.total,
            "checks": [
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status.value,
                    "severity": c.severity,
                    "evidence": c.evidence,
                    "resource_ids": c.resource_ids,
                    "recommendation": c.recommendation,
                    "remediation": c.remediation,
                    "cis_section": c.cis_section,
                    # Per-check subscription attribution for the multi-subscription
                    # fan-out; empty string on a single-subscription run.
                    "subscription_id": c.account_id,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }


_IAM_SECTION = "1 - Identity and Access Management"
_DEFENDER_SECTION = "2 - Microsoft Defender for Cloud"
_STORAGE_SECTION = "3 - Storage Accounts"
_DATABASE_SECTION = "4 - Database Services"
_LOGGING_SECTION = "5 - Logging and Monitoring"
_NETWORK_SECTION = "6 - Networking"
_VM_SECTION = "7 - Virtual Machines"
_KEYVAULT_SECTION = "8 - Key Vault"
_APPSERVICE_SECTION = "9 - App Service"


def _pass_or_no_data(result: CISCheckResult, count: int, resource_kind: str, pass_evidence: str) -> CISCheckResult:
    """PASS only when at least one resource was evaluated; zero resources is NO_DATA.

    "All 0 servers are compliant" is not evidence of compliance — it is the
    absence of evidence, reported the same way ``finalize_read_coverage`` does.
    """
    if count:
        result.status = CheckStatus.PASS
        result.evidence = pass_evidence
    else:
        result.status = CheckStatus.NO_DATA
        result.evidence = f"No {resource_kind}(s) were discovered; this check has no data and cannot report PASS."
    return result


def _enum_text(value: Any) -> str:
    """Wire value of an Azure SDK field that may be a ``str``-mixin Enum.

    The SDK deserializes known values into enum members, and ``str()`` of a
    ``(str, Enum)`` member is ``'Bypass.AZURE_SERVICES'`` — not the wire value
    ``'AzureServices'`` — so every comparison must use ``.value``.
    """
    if value is None:
        return ""
    return str(getattr(value, "value", value) or "").strip()


def _mark_unevaluable(result: CISCheckResult, exc: Exception) -> CISCheckResult:
    """Fail closed: record why the Graph evidence could not be trusted."""
    if isinstance(exc, GraphPermissionDeniedError):
        detail = "the credential lacks the read-only Microsoft Graph permission (Policy.Read.All / AccessReview.Read.All)"
    else:
        detail = "Microsoft Graph directory evidence could not be read"
    result.status = CheckStatus.ERROR
    result.evidence = (
        f"Unevaluable — {detail}; this control was not assessed and is NOT treated as passed. "
        f"Grant read-only Graph access or verify in the Microsoft Entra admin center. ({sanitize_error(exc, generic=True)})"
    )
    return result


def _ca_state(policy: dict[str, Any]) -> str:
    return str(policy.get("state") or "").strip().lower()


def _ca_enabled(policy: dict[str, Any]) -> bool:
    """A Conditional Access policy is enforced only in the ``enabled`` state.

    ``enabledForReportingButNotEnforced`` (report-only) and ``disabled`` do not
    enforce the control, so they never satisfy a benchmark requirement.
    """
    return _ca_state(policy) == "enabled"


def _ca_grant_controls(policy: dict[str, Any]) -> list[str]:
    grant = policy.get("grantControls") or {}
    controls = grant.get("builtInControls") if isinstance(grant, dict) else None
    return [str(c).strip().lower() for c in controls] if isinstance(controls, list) else []


def _ca_conditions(policy: dict[str, Any]) -> dict[str, Any]:
    conditions = policy.get("conditions")
    return conditions if isinstance(conditions, dict) else {}


def _ca_included_users(policy: dict[str, Any]) -> list[str]:
    users = _ca_conditions(policy).get("users") or {}
    inc = users.get("includeUsers") if isinstance(users, dict) else None
    return [str(u).strip().lower() for u in inc] if isinstance(inc, list) else []


def _ca_included_roles(policy: dict[str, Any]) -> list[str]:
    users = _ca_conditions(policy).get("users") or {}
    inc = users.get("includeRoles") if isinstance(users, dict) else None
    return [str(r) for r in inc] if isinstance(inc, list) else []


def _ca_included_apps(policy: dict[str, Any]) -> list[str]:
    apps = _ca_conditions(policy).get("applications") or {}
    inc = apps.get("includeApplications") if isinstance(apps, dict) else None
    return [str(a).strip().lower() for a in inc] if isinstance(inc, list) else []


def _ca_client_app_types(policy: dict[str, Any]) -> list[str]:
    types = _ca_conditions(policy).get("clientAppTypes")
    return [str(t).strip().lower() for t in types] if isinstance(types, list) else []


def _ca_sign_in_risk_levels(policy: dict[str, Any]) -> list[str]:
    levels = _ca_conditions(policy).get("signInRiskLevels")
    return [str(level).strip().lower() for level in levels] if isinstance(levels, list) else []


def _resolve_without_conditional_access(
    result: CISCheckResult, graph: Any, policies: list[dict[str, Any]], *, control: str
) -> CISCheckResult:
    """Decide a Conditional Access control when no CA policy satisfies it.

    Microsoft Entra security defaults enforce MFA (all users, administrators,
    Azure management) and block legacy authentication without any CA policy,
    and they cannot be on while CA policies are enforced. So with no enabled CA
    policy the verdict depends on the security-defaults state:

    * enabled  -> PASS (the control is enforced by security defaults);
    * disabled -> FAIL;
    * unreadable and no CA policy at all -> unevaluable (never a critical FAIL
      on missing evidence). With CA policies present, security defaults are off
      by construction and the missing CA coverage is a FAIL.
    """
    if any(_ca_enabled(p) for p in policies):
        result.status = CheckStatus.FAIL
        result.evidence = f"No enabled Conditional Access policy {control} ({len(policies)} policy(ies) reviewed)."
        return result
    try:
        defaults = graph.get(SECURITY_DEFAULTS_PATH)
    except GraphError as exc:
        if policies:
            result.status = CheckStatus.FAIL
            result.evidence = f"No enabled Conditional Access policy {control} ({len(policies)} policy(ies) reviewed)."
            return result
        return _mark_unevaluable(result, exc)
    if bool(defaults.get("isEnabled")):
        result.status = CheckStatus.PASS
        result.evidence = f"Microsoft Entra security defaults are enabled, which {control} without a Conditional Access policy."
    else:
        result.status = CheckStatus.FAIL
        result.evidence = (
            f"No enabled Conditional Access policy {control}, and Microsoft Entra security defaults are disabled "
            f"({len(policies)} policy(ies) reviewed)."
        )
    return result
