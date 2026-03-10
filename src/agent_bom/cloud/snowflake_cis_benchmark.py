"""CIS Snowflake Benchmark v1.0 — live account checks.

Runs read-only SQL queries against Snowflake ACCOUNT_USAGE and SHOW commands
to evaluate security posture against the CIS Snowflake Foundations Benchmark.
Each check returns pass/fail with evidence.

Required privileges (all read-only):
    IMPORTED PRIVILEGES on SNOWFLAKE database (for ACCOUNT_USAGE schema)
    SHOW PARAMETERS (account-level)
    SHOW NETWORK POLICIES
    SHOW USERS
    SHOW ROLES

Authentication uses standard Snowflake connector auth:
    SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER env vars +
    SSO (externalbrowser), key-pair (SNOWFLAKE_PRIVATE_KEY_PATH), or OAuth.
    SNOWFLAKE_PASSWORD is deprecated — use SSO or key-pair instead.

Install: ``pip install 'agent-bom[snowflake]'``
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
class SnowflakeCISReport:
    """Aggregated CIS Snowflake Benchmark results."""

    benchmark_version: str = "1.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    account: str = ""

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
            "benchmark": "CIS Snowflake Foundations",
            "benchmark_version": self.benchmark_version,
            "account": self.account,
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
# Helper to run SQL safely
# ---------------------------------------------------------------------------


def _run_query(cursor: Any, sql: str) -> list[dict]:
    """Execute a read-only SQL query and return results as list of dicts."""
    cursor.execute(sql)
    if cursor.description is None:
        return []
    columns = [col[0].lower() for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# ---------------------------------------------------------------------------
# Individual checks — CIS 1.x (Account and Authentication)
# ---------------------------------------------------------------------------

_AUTH_SECTION = "1 - Account and Authentication"


def _check_1_1(cursor: Any) -> CISCheckResult:
    """CIS 1.1 — Ensure MFA is enabled for all users with password authentication."""
    result = CISCheckResult(
        check_id="1.1",
        title="Ensure MFA is enabled for all users with password authentication",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_AUTH_SECTION,
        recommendation="Enable MFA for all users: ALTER USER <user> SET EXT_AUTHN_DUO = TRUE;",
    )
    rows = _run_query(
        cursor,
        """
        SELECT name, ext_authn_duo, has_password, disabled
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE deleted_on IS NULL
          AND disabled = 'false'
          AND has_password = 'true'
    """,
    )
    no_mfa = [r["name"] for r in rows if r.get("ext_authn_duo", "false").lower() != "true"]

    if no_mfa:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_mfa)} password user(s) without MFA: {', '.join(no_mfa[:5])}"
        if len(no_mfa) > 5:
            result.evidence += f" (+{len(no_mfa) - 5} more)"
        result.resource_ids = no_mfa[:20]
    else:
        result.evidence = f"All {len(rows)} password-authenticated users have MFA enabled."
    return result


def _check_1_2(cursor: Any) -> CISCheckResult:
    """CIS 1.2 — Ensure minimum password length is set to 14 or greater."""
    result = CISCheckResult(
        check_id="1.2",
        title="Ensure minimum password length is set to 14 or greater",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_AUTH_SECTION,
        recommendation="Set password policy: CREATE OR REPLACE PASSWORD POLICY ... PASSWORD_MIN_LENGTH = 14;",
    )
    rows = _run_query(
        cursor,
        """
        SELECT policy_name, password_min_length
        FROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES
        WHERE deleted IS NULL
    """,
    )
    if not rows:
        result.status = CheckStatus.FAIL
        result.evidence = "No password policies configured."
        return result

    weak = [r for r in rows if int(r.get("password_min_length", 0)) < 14]
    if weak:
        result.status = CheckStatus.FAIL
        names = [f"{r['policy_name']} (len={r['password_min_length']})" for r in weak]
        result.evidence = f"Password policies with weak min length: {', '.join(names[:5])}"
    else:
        result.evidence = f"All {len(rows)} password policies require >= 14 character minimum."
    return result


def _check_1_3(cursor: Any) -> CISCheckResult:
    """CIS 1.3 — Ensure session idle timeout is set to 4 hours or less."""
    result = CISCheckResult(
        check_id="1.3",
        title="Ensure session idle timeout is set to 4 hours (240 min) or less",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_AUTH_SECTION,
        recommendation="ALTER ACCOUNT SET SESSION_IDLE_TIMEOUT_MINS = 240;",
    )
    rows = _run_query(cursor, "SHOW PARAMETERS LIKE 'SESSION_IDLE_TIMEOUT_MINS' IN ACCOUNT")
    if rows:
        value = int(rows[0].get("value", 0))
        if value > 240:
            result.status = CheckStatus.FAIL
            result.evidence = f"Session idle timeout is {value} minutes (max recommended: 240)."
        else:
            result.evidence = f"Session idle timeout is {value} minutes."
    else:
        result.evidence = "Session idle timeout parameter not found (using default)."
    return result


def _check_1_4(cursor: Any) -> CISCheckResult:
    """CIS 1.4 — Ensure ACCOUNTADMIN role is granted to no more than 2 users."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure ACCOUNTADMIN role is granted to no more than 2 users",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_AUTH_SECTION,
        recommendation="Limit ACCOUNTADMIN grants to a maximum of 2 users.",
    )
    rows = _run_query(
        cursor,
        """
        SELECT grantee_name
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE role = 'ACCOUNTADMIN'
          AND deleted_on IS NULL
    """,
    )
    count = len(rows)
    users = [r["grantee_name"] for r in rows]
    if count > 2:
        result.status = CheckStatus.FAIL
        result.evidence = f"ACCOUNTADMIN granted to {count} users: {', '.join(users[:5])}"
        if count > 5:
            result.evidence += f" (+{count - 5} more)"
        result.resource_ids = users[:20]
    else:
        result.evidence = f"ACCOUNTADMIN granted to {count} user(s): {', '.join(users)}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 2.x (Network Security)
# ---------------------------------------------------------------------------

_NETWORK_SECTION = "2 - Network Security"


def _check_2_1(cursor: Any) -> CISCheckResult:
    """CIS 2.1 — Ensure network policies are configured at the account level."""
    result = CISCheckResult(
        check_id="2.1",
        title="Ensure network policies are configured at the account level",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_NETWORK_SECTION,
        recommendation="Create and apply a network policy: ALTER ACCOUNT SET NETWORK_POLICY = '<policy>';",
    )
    rows = _run_query(cursor, "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT")
    if rows:
        policy_name = rows[0].get("value", "")
        if not policy_name:
            result.status = CheckStatus.FAIL
            result.evidence = "No account-level network policy is set."
        else:
            result.evidence = f"Account-level network policy: {policy_name}"
    else:
        result.status = CheckStatus.FAIL
        result.evidence = "Network policy parameter not found."
    return result


def _check_2_2(cursor: Any) -> CISCheckResult:
    """CIS 2.2 — Ensure network policies do not allow unrestricted access (0.0.0.0/0)."""
    result = CISCheckResult(
        check_id="2.2",
        title="Ensure network policies do not allow unrestricted access (0.0.0.0/0)",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_NETWORK_SECTION,
        recommendation="Remove 0.0.0.0/0 from all network policy allowed IP lists.",
    )
    rows = _run_query(cursor, "SHOW NETWORK POLICIES")
    if not rows:
        result.status = CheckStatus.NOT_APPLICABLE
        result.evidence = "No network policies configured."
        return result

    open_policies = []
    for row in rows:
        allowed = str(row.get("allowed_ip_list", ""))
        if "0.0.0.0/0" in allowed:
            open_policies.append(row.get("name", "unknown"))

    if open_policies:
        result.status = CheckStatus.FAIL
        result.evidence = f"Network policies allowing 0.0.0.0/0: {', '.join(open_policies)}"
        result.resource_ids = open_policies
    else:
        result.evidence = f"All {len(rows)} network policies restrict access properly."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 3.x (Data Protection)
# ---------------------------------------------------------------------------

_DATA_SECTION = "3 - Data Protection"


def _check_3_1(cursor: Any) -> CISCheckResult:
    """CIS 3.1 — Ensure Tri-Secret Secure (customer-managed key) is enabled."""
    result = CISCheckResult(
        check_id="3.1",
        title="Ensure Tri-Secret Secure (customer-managed key) is enabled",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_DATA_SECTION,
        recommendation="Contact Snowflake support to enable Tri-Secret Secure with your cloud KMS.",
    )
    rows = _run_query(cursor, "SHOW PARAMETERS LIKE 'PERIODIC_DATA_REKEYING' IN ACCOUNT")
    if rows:
        value = str(rows[0].get("value", "false")).lower()
        if value != "true":
            result.status = CheckStatus.FAIL
            result.evidence = "Periodic data rekeying is not enabled (Tri-Secret Secure not configured)."
        else:
            result.evidence = "Periodic data rekeying is enabled."
    else:
        result.status = CheckStatus.FAIL
        result.evidence = "Periodic data rekeying parameter not found."
    return result


def _check_3_2(cursor: Any) -> CISCheckResult:
    """CIS 3.2 — Ensure data sharing is restricted to authorized accounts."""
    result = CISCheckResult(
        check_id="3.2",
        title="Ensure data sharing is restricted to authorized accounts only",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_DATA_SECTION,
        recommendation="Review outbound shares and remove unauthorized consumers.",
    )
    rows = _run_query(
        cursor,
        """
        SELECT database_name, name, kind
        FROM SNOWFLAKE.ACCOUNT_USAGE.SHARES
        WHERE deleted IS NULL
          AND kind = 'OUTBOUND'
    """,
    )
    if rows:
        share_names = [f"{r['database_name']}.{r['name']}" for r in rows]
        result.evidence = f"{len(rows)} outbound share(s) found: {', '.join(share_names[:5])}"
        if len(share_names) > 5:
            result.evidence += f" (+{len(share_names) - 5} more)"
        # Informational — not auto-failing, but flagging for review
        result.evidence += ". Review these shares for unauthorized consumers."
    else:
        result.evidence = "No outbound data shares configured."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 4.x (Monitoring and Logging)
# ---------------------------------------------------------------------------

_MONITORING_SECTION = "4 - Monitoring and Logging"


def _check_4_1(cursor: Any) -> CISCheckResult:
    """CIS 4.1 — Ensure access history is enabled and being collected."""
    result = CISCheckResult(
        check_id="4.1",
        title="Ensure access history is enabled and being collected",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_MONITORING_SECTION,
        recommendation="Ensure IMPORTED PRIVILEGES on SNOWFLAKE database and query ACCESS_HISTORY regularly.",
    )
    try:
        rows = _run_query(
            cursor,
            """
            SELECT COUNT(*) as cnt
            FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY
            WHERE query_start_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
        """,
        )
        count = rows[0]["cnt"] if rows else 0
        if count == 0:
            result.status = CheckStatus.FAIL
            result.evidence = "No access history records in the last 7 days."
        else:
            result.evidence = f"Access history active: {count} records in the last 7 days."
    except Exception:
        result.status = CheckStatus.ERROR
        result.evidence = "Cannot query ACCESS_HISTORY. Ensure IMPORTED PRIVILEGES on SNOWFLAKE database."
    return result


def _check_4_2(cursor: Any) -> CISCheckResult:
    """CIS 4.2 — Ensure login history shows no failed authentication patterns."""
    result = CISCheckResult(
        check_id="4.2",
        title="Ensure login history shows no excessive failed authentication attempts",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Investigate users with excessive failed logins and enforce MFA.",
    )
    rows = _run_query(
        cursor,
        """
        SELECT user_name, COUNT(*) as fail_count
        FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
        WHERE is_success = 'NO'
          AND event_timestamp >= DATEADD(day, -7, CURRENT_TIMESTAMP())
        GROUP BY user_name
        HAVING COUNT(*) > 10
        ORDER BY fail_count DESC
    """,
    )
    if rows:
        result.status = CheckStatus.FAIL
        users = [f"{r['user_name']} ({r['fail_count']} failures)" for r in rows[:5]]
        result.evidence = f"Users with >10 failed logins (7d): {', '.join(users)}"
        result.resource_ids = [r["user_name"] for r in rows[:20]]
    else:
        result.evidence = "No users with excessive failed login attempts in the last 7 days."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 5.x (Access Control)
# ---------------------------------------------------------------------------

_ACCESS_SECTION = "5 - Access Control"


def _check_5_1(cursor: Any) -> CISCheckResult:
    """CIS 5.1 — Ensure the PUBLIC role has no direct privilege grants on objects."""
    result = CISCheckResult(
        check_id="5.1",
        title="Ensure the PUBLIC role has no direct privilege grants on objects",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_ACCESS_SECTION,
        recommendation="Revoke all grants from the PUBLIC role: REVOKE ALL ON <object> FROM ROLE PUBLIC;",
    )
    rows = _run_query(
        cursor,
        """
        SELECT privilege, granted_on, name
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE grantee_name = 'PUBLIC'
          AND deleted_on IS NULL
          AND granted_on NOT IN ('ROLE')
          AND privilege != 'USAGE'
    """,
    )
    if rows:
        result.status = CheckStatus.FAIL
        grants = [f"{r['privilege']} on {r['granted_on']} {r['name']}" for r in rows[:5]]
        result.evidence = f"{len(rows)} grant(s) to PUBLIC role: {', '.join(grants)}"
        if len(rows) > 5:
            result.evidence += f" (+{len(rows) - 5} more)"
    else:
        result.evidence = "PUBLIC role has no direct object grants (excluding USAGE)."
    return result


def _check_5_2(cursor: Any) -> CISCheckResult:
    """CIS 5.2 — Ensure no users have ACCOUNTADMIN as their default role."""
    result = CISCheckResult(
        check_id="5.2",
        title="Ensure no users have ACCOUNTADMIN as their default role",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_ACCESS_SECTION,
        recommendation="Change default role: ALTER USER <user> SET DEFAULT_ROLE = '<other_role>';",
    )
    rows = _run_query(
        cursor,
        """
        SELECT name, default_role
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE deleted_on IS NULL
          AND disabled = 'false'
          AND default_role = 'ACCOUNTADMIN'
    """,
    )
    if rows:
        result.status = CheckStatus.FAIL
        users = [r["name"] for r in rows]
        result.evidence = f"{len(users)} user(s) with ACCOUNTADMIN as default role: {', '.join(users[:5])}"
        if len(users) > 5:
            result.evidence += f" (+{len(users) - 5} more)"
        result.resource_ids = users[:20]
    else:
        result.evidence = "No active users have ACCOUNTADMIN as their default role."
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    checks: list[str] | None = None,
) -> SnowflakeCISReport:
    """Run CIS Snowflake Benchmark v1.0 checks.

    Uses standard Snowflake connector authentication (env vars or params).
    Only read-only queries are executed.

    Args:
        account: Snowflake account identifier.
        user: Snowflake user name.
        authenticator: Authentication method (externalbrowser, snowflake, etc.).
        checks: Optional list of check IDs to run (e.g. ``["1.1", "2.1"]``).

    Returns:
        SnowflakeCISReport with per-check pass/fail results.
    """
    try:
        import snowflake.connector
        from snowflake.connector.errors import DatabaseError
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for CIS Snowflake Benchmark checks. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = account or os.environ.get("SNOWFLAKE_ACCOUNT", "")
    resolved_user = user or os.environ.get("SNOWFLAKE_USER", "")

    if not resolved_account:
        raise CloudDiscoveryError("SNOWFLAKE_ACCOUNT not set. Provide --snowflake-account or set the env var.")

    conn_kwargs: dict[str, str] = {
        "account": resolved_account,
        "user": resolved_user,
    }
    from .snowflake import _resolve_snowflake_auth

    _resolve_snowflake_auth(conn_kwargs, authenticator)

    try:
        conn = snowflake.connector.connect(**conn_kwargs)
    except (DatabaseError, Exception) as exc:
        raise CloudDiscoveryError(f"Could not connect to Snowflake: {exc}")

    report = SnowflakeCISReport(account=resolved_account)

    all_checks: list[tuple[str, callable]] = [
        ("1.1", _check_1_1),
        ("1.2", _check_1_2),
        ("1.3", _check_1_3),
        ("1.4", _check_1_4),
        ("2.1", _check_2_1),
        ("2.2", _check_2_2),
        ("3.1", _check_3_1),
        ("3.2", _check_3_2),
        ("4.1", _check_4_1),
        ("4.2", _check_4_2),
        ("5.1", _check_5_1),
        ("5.2", _check_5_2),
    ]

    try:
        cursor = conn.cursor()
        for check_id, check_fn in all_checks:
            if checks and check_id not in checks:
                continue
            try:
                check_result = check_fn(cursor)
                report.checks.append(check_result)
            except Exception as exc:
                logger.warning("CIS Snowflake check %s failed: %s", check_id, exc)
                report.checks.append(
                    CISCheckResult(
                        check_id=check_id,
                        title=check_fn.__doc__.split("—")[1].strip().rstrip(".") if check_fn.__doc__ else "",
                        status=CheckStatus.ERROR,
                        severity="unknown",
                        evidence=f"Query error: {exc}",
                    )
                )
    finally:
        conn.close()

    return report
