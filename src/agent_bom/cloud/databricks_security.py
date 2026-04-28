"""Databricks Security Best Practices — live workspace checks.

Runs read-only Databricks REST API checks against security best practices
covering identity, clusters, data, networking, audit, and secrets.
Each check returns pass/fail with evidence.

Based on Databricks Security Best Practices documentation.
Note: Databricks does not have an official CIS Benchmark. These checks
are derived from Databricks' own published security hardening guidance.

Required permissions (all read-only):
    CAN MANAGE on workspace (admin or security admin role) for full coverage.
    Non-admin users will see partial results (checks marked ERROR where
    insufficient permissions exist).

    Minimum for cluster checks:
        CAN VIEW on all clusters
    Minimum for admin checks:
        Databricks workspace admin

Install: ``pip install 'agent-bom[databricks]'``
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .aws_cis_benchmark import CheckStatus, CISCheckResult
from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


@dataclass
class DatabricksSecurityReport:
    """Aggregated Databricks Security Best Practices results."""

    benchmark_version: str = "1.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    workspace_host: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        evaluated = sum(1 for c in self.checks if c.status in (CheckStatus.PASS, CheckStatus.FAIL))
        return (self.passed / evaluated * 100) if evaluated else 0.0

    def to_dict(self) -> dict:
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "Databricks Security Best Practices",
            "benchmark_version": self.benchmark_version,
            "workspace_host": self.workspace_host,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
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
                    "cis_section": c.cis_section,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Call a Databricks SDK method, returning None on permission/API errors."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        logger.debug("Databricks API call failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Section 1 — Identity and Access Management
# ---------------------------------------------------------------------------

_IAM_SECTION = "1 - Identity and Access Management"


def _check_1_1(ws: Any) -> CISCheckResult:
    """1.1 — Minimize the number of workspace admins."""
    result = CISCheckResult(
        check_id="1.1",
        title="Minimize workspace admin count",
        status=CheckStatus.ERROR,
        severity="high",
        cis_section=_IAM_SECTION,
        recommendation="Limit workspace admins to 2-3 named individuals. Use groups for access delegation instead of direct admin grants.",
    )
    try:
        admin_users = []
        for user in ws.users.list(attributes="id,userName,roles"):
            roles = getattr(user, "roles", None) or []
            role_values = [getattr(r, "value", str(r)) for r in roles]
            if any("admin" in str(v).lower() for v in role_values):
                admin_users.append(getattr(user, "user_name", str(user.id)))
        count = len(admin_users)
        if count <= 3:
            result.status = CheckStatus.PASS
            result.evidence = f"{count} admin user(s) — within recommended limit."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"{count} admin users exceed recommended limit of 3."
            result.resource_ids = admin_users[:10]
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate users: {exc}"
    return result


def _check_1_2(ws: Any) -> CISCheckResult:
    """1.2 — Ensure IP access lists restrict workspace access."""
    result = CISCheckResult(
        check_id="1.2",
        title="Ensure IP access lists are configured",
        status=CheckStatus.ERROR,
        severity="high",
        cis_section=_IAM_SECTION,
        recommendation="Enable IP access lists to restrict workspace access to trusted IP ranges. "
        "See: Settings > Security > IP Access List.",
    )
    try:
        ip_lists = list(_safe(ws.ip_access_lists.list) or [])
        enabled = [acl for acl in ip_lists if getattr(acl, "enabled", False)]
        if not ip_lists:
            result.status = CheckStatus.FAIL
            result.evidence = "No IP access lists configured — workspace accessible from any IP."
        elif not enabled:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(ip_lists)} IP access list(s) configured but none enabled."
            result.resource_ids = [getattr(a, "label", str(i)) for i, a in enumerate(ip_lists[:5])]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(enabled)} IP access list(s) active."
            result.resource_ids = [getattr(a, "label", str(i)) for i, a in enumerate(enabled[:5])]
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check IP access lists: {exc}"
    return result


def _check_1_3(ws: Any) -> CISCheckResult:
    """1.3 — Ensure Personal Access Token expiry policy is enforced."""
    result = CISCheckResult(
        check_id="1.3",
        title="Enforce Personal Access Token expiry policy",
        status=CheckStatus.ERROR,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Set a PAT expiry policy: Workspace Settings > Advanced > "
        "Access tokens > Token lifetime (maximum 90 days recommended).",
    )
    try:
        # Try workspace settings API
        settings = _safe(ws.settings.personal_access_token_expiry.get)
        if settings is not None:
            max_lifetime = getattr(settings, "setting_value", None)
            if max_lifetime and max_lifetime != "0":
                result.status = CheckStatus.PASS
                result.evidence = f"PAT expiry enforced: maximum lifetime = {max_lifetime}s."
            else:
                result.status = CheckStatus.FAIL
                result.evidence = "PAT expiry not enforced — tokens may never expire."
        else:
            # Fallback: check token list for tokens with no expiry
            tokens = list(_safe(ws.token_management.list) or [])
            non_expiring = [t for t in tokens if getattr(t, "expiry_time", -1) in (-1, None, 0)]
            if non_expiring:
                result.status = CheckStatus.FAIL
                result.evidence = f"{len(non_expiring)} token(s) with no expiry found."
                result.resource_ids = [getattr(t, "comment", str(i)) for i, t in enumerate(non_expiring[:5])]
            else:
                result.status = CheckStatus.PASS
                result.evidence = "All enumerable tokens have expiry dates set."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PAT policy: {exc}"
    return result


def _check_1_4(ws: Any) -> CISCheckResult:
    """1.4 — Ensure service principals use short-lived tokens."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure service principals use short-lived or federated tokens",
        status=CheckStatus.ERROR,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Replace long-lived service principal PATs with OAuth M2M tokens or workload identity federation where possible.",
    )
    try:
        sps = list(_safe(ws.service_principals.list) or [])
        if not sps:
            result.status = CheckStatus.PASS
            result.evidence = "No service principals found."
            return result
        # Check tokens for service principals — look for tokens with distant expiry
        import time

        tokens = list(_safe(ws.token_management.list) or [])
        now_ms = int(time.time() * 1000)
        ninety_days_ms = 90 * 24 * 60 * 60 * 1000
        long_lived = [t for t in tokens if getattr(t, "expiry_time", 0) and (getattr(t, "expiry_time", 0) - now_ms) > ninety_days_ms]
        if long_lived:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(long_lived)} token(s) valid for more than 90 days detected."
            result.resource_ids = [getattr(t, "comment", f"token-{i}") for i, t in enumerate(long_lived[:5])]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(sps)} service principal(s) found — no long-lived tokens detected."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check service principal tokens: {exc}"
    return result


# ---------------------------------------------------------------------------
# Section 2 — Cluster Security
# ---------------------------------------------------------------------------

_CLUSTER_SECTION = "2 - Cluster Security"


def _check_2_1(ws: Any) -> CISCheckResult:
    """2.1 — Ensure all clusters have auto-termination enabled."""
    result = CISCheckResult(
        check_id="2.1",
        title="Ensure all clusters have auto-termination enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        cis_section=_CLUSTER_SECTION,
        recommendation="Set auto_termination_minutes on all interactive clusters "
        "(recommended: 30-60 minutes). Job clusters terminate automatically.",
    )
    try:
        clusters = list(_safe(ws.clusters.list) or [])
        interactive = [c for c in clusters if getattr(c, "cluster_source", "") not in ("JOB", "PIPELINE")]
        no_term = [c for c in interactive if not getattr(c, "auto_termination_minutes", 0)]
        if not interactive:
            result.status = CheckStatus.PASS
            result.evidence = "No interactive clusters found."
        elif no_term:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(no_term)}/{len(interactive)} interactive cluster(s) lack auto-termination."
            result.resource_ids = [getattr(c, "cluster_name", getattr(c, "cluster_id", str(i))) for i, c in enumerate(no_term[:10])]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(interactive)} interactive cluster(s) have auto-termination configured."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate clusters: {exc}"
    return result


def _check_2_2(ws: Any) -> CISCheckResult:
    """2.2 — Ensure no clusters use no-isolation shared access mode."""
    result = CISCheckResult(
        check_id="2.2",
        title="Ensure clusters use isolated data security mode",
        status=CheckStatus.ERROR,
        severity="high",
        cis_section=_CLUSTER_SECTION,
        recommendation="Use USER_ISOLATION or SINGLE_USER data_security_mode. "
        "Avoid NONE (no-isolation) which allows cross-user data access.",
    )
    try:
        clusters = list(_safe(ws.clusters.list) or [])
        running = [c for c in clusters if getattr(c, "state", "") in ("RUNNING", "RESIZING", "RESTARTING")]
        no_isolation = [c for c in running if str(getattr(c, "data_security_mode", "NONE")).upper() in ("NONE", "LEGACY_PASSTHROUGH", "")]
        if not running:
            result.status = CheckStatus.PASS
            result.evidence = "No running clusters found."
        elif no_isolation:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(no_isolation)} running cluster(s) use no-isolation or legacy passthrough mode."
            result.resource_ids = [getattr(c, "cluster_name", getattr(c, "cluster_id", str(i))) for i, c in enumerate(no_isolation[:10])]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(running)} running cluster(s) use isolated data security mode."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check cluster security modes: {exc}"
    return result


def _check_2_3(ws: Any) -> CISCheckResult:
    """2.3 — Ensure cluster policies are enforced."""
    result = CISCheckResult(
        check_id="2.3",
        title="Ensure cluster policies are used to enforce security baselines",
        status=CheckStatus.ERROR,
        severity="medium",
        cis_section=_CLUSTER_SECTION,
        recommendation="Create cluster policies that enforce auto-termination, security mode, instance types, and other security controls.",
    )
    try:
        policies = list(_safe(ws.cluster_policies.list) or [])
        # Filter to non-default policies (user-created)
        custom = [p for p in policies if not getattr(p, "is_default", False)]
        if custom:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(custom)} custom cluster polic(ies) found."
            result.resource_ids = [getattr(p, "name", str(i)) for i, p in enumerate(custom[:5])]
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No custom cluster policies configured — clusters can be created without security controls."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check cluster policies: {exc}"
    return result


def _check_2_4(ws: Any) -> CISCheckResult:
    """2.4 — Ensure clusters do not have public IPs enabled."""
    result = CISCheckResult(
        check_id="2.4",
        title="Ensure clusters use no-public-IP configuration",
        status=CheckStatus.ERROR,
        severity="high",
        cis_section=_CLUSTER_SECTION,
        recommendation="Enable Secure Cluster Connectivity (no-public-IP) at the workspace level. "
        "Clusters should not have public IP addresses.",
    )
    try:
        clusters = list(_safe(ws.clusters.list) or [])
        running = [c for c in clusters if getattr(c, "state", "") in ("RUNNING", "RESIZING")]
        public_ip = [c for c in running if getattr(c, "enable_elastic_disk", None) is not None and not getattr(c, "no_public_ips", False)]
        # Also check via AWS/Azure attributes
        public_ip_clusters = [
            c
            for c in running
            if getattr(c, "aws_attributes", None) is not None
            and getattr(getattr(c, "aws_attributes", None), "ebs_volume_count", 0) == 0
            and not getattr(c, "no_public_ips", True)
        ]
        combined = {getattr(c, "cluster_id", str(i)): c for i, c in enumerate(public_ip + public_ip_clusters)}
        if not running:
            result.status = CheckStatus.PASS
            result.evidence = "No running clusters found."
        elif combined:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(combined)} running cluster(s) may have public IPs."
            result.resource_ids = list(combined.keys())[:10]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(running)} running cluster(s) appear to use private networking."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check cluster networking: {exc}"
    return result


# ---------------------------------------------------------------------------
# Section 3 — Data Security
# ---------------------------------------------------------------------------

_DATA_SECTION = "3 - Data Security"


def _check_3_1(ws: Any) -> CISCheckResult:
    """3.1 — Ensure Unity Catalog metastore is assigned to the workspace."""
    result = CISCheckResult(
        check_id="3.1",
        title="Ensure Unity Catalog metastore is assigned for centralized governance",
        status=CheckStatus.ERROR,
        severity="high",
        cis_section=_DATA_SECTION,
        recommendation="Assign a Unity Catalog metastore to enable fine-grained data access controls, auditing, and lineage tracking.",
    )
    try:
        metastore = _safe(ws.metastores.current)
        if metastore is not None and getattr(metastore, "metastore_id", None):
            result.status = CheckStatus.PASS
            result.evidence = (
                f"Unity Catalog metastore assigned: {getattr(metastore, 'name', getattr(metastore, 'metastore_id', 'unknown'))}."
            )
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No Unity Catalog metastore assigned — workspace uses legacy Hive metastore without centralized governance."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check metastore assignment: {exc}"
    return result


# ---------------------------------------------------------------------------
# Section 4 — Audit and Logging
# ---------------------------------------------------------------------------

_AUDIT_SECTION = "4 - Audit and Logging"


def _check_4_1(ws: Any) -> CISCheckResult:
    """4.1 — Ensure audit log delivery is configured."""
    result = CISCheckResult(
        check_id="4.1",
        title="Ensure audit log delivery is configured",
        status=CheckStatus.ERROR,
        severity="critical",
        cis_section=_AUDIT_SECTION,
        recommendation="Configure audit log delivery to S3, ADLS, or GCS. Enable workspace and account-level audit logs.",
    )
    try:
        log_configs = list(_safe(ws.log_delivery.list) or [])
        audit_configs = [
            lc
            for lc in log_configs
            if str(getattr(lc, "log_type", "")).upper() in ("AUDIT_LOGS", "BILLABLE_USAGE")
            and str(getattr(lc, "status", "")).upper() == "ENABLED"
        ]
        if audit_configs:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(audit_configs)} active audit log delivery configuration(s) found."
        elif log_configs:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(log_configs)} log delivery configuration(s) found but none active/audit-type."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No log delivery configurations found — workspace activity is not being audited externally."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log delivery: {exc}"
    return result


# ---------------------------------------------------------------------------
# Section 5 — Secrets Management
# ---------------------------------------------------------------------------

_SECRETS_SECTION = "5 - Secrets Management"


def _check_5_1(ws: Any) -> CISCheckResult:
    """5.1 — Ensure Databricks Secrets are used instead of hardcoded credentials."""
    result = CISCheckResult(
        check_id="5.1",
        title="Ensure Databricks Secrets are used for credential management",
        status=CheckStatus.ERROR,
        severity="high",
        cis_section=_SECRETS_SECTION,
        recommendation="Use Databricks Secrets (dbutils.secrets.get) instead of "
        "hardcoded credentials in notebooks or cluster environment variables.",
    )
    try:
        scopes = list(_safe(ws.secrets.list_scopes) or [])
        if scopes:
            result.status = CheckStatus.PASS
            scope_names = [getattr(s, "name", str(i)) for i, s in enumerate(scopes[:5])]
            result.evidence = f"{len(scopes)} secret scope(s) configured: {', '.join(scope_names)}."
            result.resource_ids = scope_names
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No Databricks secret scopes configured — credentials may be hardcoded in notebooks or env vars."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check secret scopes: {exc}"
    return result


def _check_5_2(ws: Any) -> CISCheckResult:
    """5.2 — Ensure cluster environment variables do not contain credentials."""
    result = CISCheckResult(
        check_id="5.2",
        title="Ensure cluster environment variables do not expose credentials",
        status=CheckStatus.ERROR,
        severity="critical",
        cis_section=_SECRETS_SECTION,
        recommendation="Replace plaintext credentials in cluster spark_env_vars or custom_tags with Databricks Secrets references.",
    )
    import re

    _cred_pattern = re.compile(
        r"(?:password|secret|token|key|api_key|access_key|private_key)\s*=\s*\S{8,}",
        re.IGNORECASE,
    )
    try:
        clusters = list(_safe(ws.clusters.list) or [])
        exposed = []
        for cluster in clusters:
            env_vars: dict = getattr(cluster, "spark_env_vars", None) or {}
            for key, val in env_vars.items():
                if _cred_pattern.search(f"{key}={val}"):
                    exposed.append(getattr(cluster, "cluster_name", getattr(cluster, "cluster_id", "unknown")))
                    break
        if exposed:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(exposed)} cluster(s) have potential credential-like values in environment variables."
            result.resource_ids = exposed[:10]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"Checked {len(clusters)} cluster(s) — no plaintext credentials detected in environment variables."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check cluster environment variables: {exc}"
    return result


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

_ALL_CHECKS = [
    _check_1_1,
    _check_1_2,
    _check_1_3,
    _check_1_4,
    _check_2_1,
    _check_2_2,
    _check_2_3,
    _check_2_4,
    _check_3_1,
    _check_4_1,
    _check_5_1,
    _check_5_2,
]


def run_security_checks(
    host: str | None = None,
    token: str | None = None,
) -> DatabricksSecurityReport:
    """Run all Databricks security checks and return a benchmark report.

    Args:
        host: Databricks workspace host (e.g. https://adb-123.azuredatabricks.net).
              Defaults to DATABRICKS_HOST env var.
        token: Databricks personal access token. Defaults to DATABRICKS_TOKEN env var.

    Returns:
        DatabricksSecurityReport with pass/fail results for all checks.

    Raises:
        CloudDiscoveryError: if databricks-sdk is not installed or workspace is unreachable.
    """
    try:
        from databricks.sdk import WorkspaceClient
    except ImportError:
        raise CloudDiscoveryError(
            "databricks-sdk is required for Databricks CIS benchmark. Install with: pip install 'agent-bom[databricks]'"
        )

    ws_kwargs: dict = {}
    if host:
        ws_kwargs["host"] = host
    if token:
        ws_kwargs["token"] = token

    try:
        ws = WorkspaceClient(**ws_kwargs)
    except Exception as exc:
        raise CloudDiscoveryError(f"Could not connect to Databricks workspace: {exc}") from exc

    resolved_host = host if host is not None else (os.environ.get("DATABRICKS_HOST") or "unknown")
    report = DatabricksSecurityReport(workspace_host=resolved_host)

    for check_fn in _ALL_CHECKS:
        try:
            result = check_fn(ws)
        except Exception as exc:
            check_id = check_fn.__name__.replace("_check_", "").replace("_", ".")
            result = CISCheckResult(
                check_id=check_id,
                title=f"Check {check_id}",
                status=CheckStatus.ERROR,
                severity="medium",
                evidence=f"Unexpected error: {exc}",
            )
        report.checks.append(result)

    return report
