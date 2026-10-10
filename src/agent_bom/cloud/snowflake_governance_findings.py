"""Snowflake governance finding derivation over a mined GovernanceReport."""

from __future__ import annotations

import logging

from agent_bom.governance import (
    AccessRecord,
    DataClassification,
    GovernanceCategory,
    GovernanceFinding,
    GovernanceReport,
    GovernanceSeverity,
    PrivilegeGrant,
)

from .snowflake_common import _sf

# Log under the façade's logger so existing log routing and filters keep applying.
logger = logging.getLogger("agent_bom.cloud.snowflake")


# ---------------------------------------------------------------------------
# Finding derivation — analyze raw data to produce governance risk findings
# ---------------------------------------------------------------------------


def _derive_findings(report: GovernanceReport) -> list[GovernanceFinding]:
    """Analyze raw governance data and derive risk findings."""
    findings: list[GovernanceFinding] = []

    findings.extend(_find_write_access_risks(report))
    findings.extend(_find_elevated_privilege_risks(report))
    findings.extend(_find_sensitive_data_access(report))
    findings.extend(_sf()._find_agent_usage_anomalies(report))

    # Sort by severity
    from agent_bom.core.severity import severity_worst_first_rank

    findings.sort(key=lambda f: severity_worst_first_rank(f.severity.value if hasattr(f.severity, "value") else str(f.severity)))

    return findings


def _access_actor(rec: AccessRecord, record_index: int) -> tuple[str, str]:
    """Group only on a recorded actor, or keep unattributed query scopes apart."""
    for kind, name in (("role", rec.role_name), ("user", rec.user_name), ("query", rec.query_id)):
        if name and name.strip():
            return kind, name
    # No actor or query identifier is available. Do not turn unrelated missing
    # values into one principal or infer that these records share a session.
    return "record", str(record_index + 1)


def _access_actor_context(actor: tuple[str, str]) -> tuple[str, str, str]:
    """Return a typed title, observation context and known principal name."""
    kind, name = actor
    if kind == "role":
        return f"role {name}", f"under recorded role '{name}'", name
    if kind == "user":
        return f"user {name}", f"for user '{name}' (query role unavailable)", name
    return f"{kind} {name}", f"for {kind} '{name}' (identity unavailable)", ""


def _find_write_access_risks(report: GovernanceReport) -> list[GovernanceFinding]:
    """Flag historical write observations without inventing an unknown actor."""
    findings: list[GovernanceFinding] = []
    write_ops: dict[tuple[str, str], set[str]] = {}

    for index, rec in enumerate(report.access_records):
        if rec.is_write:
            write_ops.setdefault(_access_actor(rec, index), set()).add(rec.object_name)

    for actor, tables in write_ops.items():
        actor_label, context, principal = _access_actor_context(actor)
        broad = len(tables) >= 5
        findings.append(
            GovernanceFinding(
                category=GovernanceCategory.ACCESS,
                severity=GovernanceSeverity.HIGH if broad else GovernanceSeverity.MEDIUM,
                title=f"{'Broad write observations' if broad else 'Write observation'}: {actor_label}",
                description=(
                    f"Access history records write-related activity {context} on {len(tables)} distinct object(s) "
                    f"in the analysis window: {', '.join(sorted(tables)[:5])}"
                ),
                agent_or_role=principal,
                details={
                    "tables": sorted(tables)[:20],
                    "actor_type": actor[0],
                    "actor_id": actor[1],
                    "evidence_kind": "historical_access",
                },
            )
        )

    return findings


def _find_elevated_privilege_risks(report: GovernanceReport) -> list[GovernanceFinding]:
    """Flag roles with dangerous privileges (OWNERSHIP, ALL, CREATE ROLE, etc.)."""
    findings: list[GovernanceFinding] = []
    elevated_by_role: dict[str, list[PrivilegeGrant]] = {}

    for grant in report.privilege_grants:
        if grant.is_elevated:
            elevated_by_role.setdefault(grant.grantee, []).append(grant)

    for role, role_grants in elevated_by_role.items():
        priv_set = {g.privilege for g in role_grants}
        if "OWNERSHIP" in priv_set or "ALL" in priv_set or "ALL PRIVILEGES" in priv_set:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.PRIVILEGE,
                    severity=GovernanceSeverity.CRITICAL,
                    title=f"Elevated privileges: {role}",
                    description=(
                        f"Role '{role}' has {', '.join(sorted(priv_set))} privileges. "
                        f"If an agent runs under this role, it has full control over "
                        f"granted objects."
                    ),
                    agent_or_role=role,
                    details={
                        "privileges": sorted(priv_set),
                        "grant_count": len(role_grants),
                        "objects": sorted({g.object_name for g in role_grants})[:10],
                    },
                )
            )
        else:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.PRIVILEGE,
                    severity=GovernanceSeverity.HIGH,
                    title=f"Elevated privileges: {role}",
                    description=(f"Role '{role}' has elevated privileges: {', '.join(sorted(priv_set))}"),
                    agent_or_role=role,
                    details={
                        "privileges": sorted(priv_set),
                        "grant_count": len(role_grants),
                    },
                )
            )

    return findings


def _find_sensitive_data_access(report: GovernanceReport) -> list[GovernanceFinding]:
    """Cross-reference TAG_REFERENCES with ACCESS_HISTORY to find sensitive data access."""
    findings: list[GovernanceFinding] = []

    # Build set of tagged (sensitive) objects
    sensitive_objects: dict[str, list[DataClassification]] = {}
    for tag in report.data_classifications:
        sensitive_objects.setdefault(tag.object_name.upper(), []).append(tag)

    if not sensitive_objects:
        return findings

    # Check which access records touch sensitive objects
    sensitive_access: dict[tuple[str, str], dict[str, set[str]]] = {}
    for index, rec in enumerate(report.access_records):
        obj_upper = rec.object_name.upper()
        if obj_upper in sensitive_objects:
            tags_for_obj = sensitive_objects[obj_upper]
            tag_names = {t.tag_name for t in tags_for_obj}
            sa = sensitive_access.setdefault(_access_actor(rec, index), {})
            sa.setdefault(obj_upper, set()).update(tag_names)

    for actor, obj_tags in sensitive_access.items():
        actor_label, context, principal = _access_actor_context(actor)
        actor_evidence = {"actor_type": actor[0], "actor_id": actor[1], "evidence_kind": "historical_access"}
        pii_tables = [obj for obj, tags in obj_tags.items() if any("PII" in t.upper() or "PHI" in t.upper() for t in tags)]
        if pii_tables:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.DATA_CLASSIFICATION,
                    severity=GovernanceSeverity.CRITICAL,
                    title=f"PII/PHI-tagged object access: {actor_label}",
                    description=(
                        f"Access history {context} references {len(pii_tables)} PII/PHI-tagged object(s): {', '.join(pii_tables[:5])}"
                    ),
                    agent_or_role=principal,
                    details={"pii_tables": pii_tables[:20], **actor_evidence},
                )
            )

        other_sensitive = [obj for obj, tags in obj_tags.items() if obj not in pii_tables]
        if other_sensitive:
            all_tags = set()
            for obj in other_sensitive:
                all_tags.update(obj_tags[obj])
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.DATA_CLASSIFICATION,
                    severity=GovernanceSeverity.HIGH,
                    title=f"Classified object access: {actor_label}",
                    description=(
                        f"Access history {context} references {len(other_sensitive)} classified object(s) "
                        f"with tags: {', '.join(sorted(all_tags))}"
                    ),
                    agent_or_role=principal,
                    details={
                        "tables": other_sensitive[:20],
                        "tags": sorted(all_tags),
                        **actor_evidence,
                    },
                )
            )

    return findings


def _aggregate_agent_usage(report: GovernanceReport) -> dict[str, dict]:
    """Aggregate CORTEX_AGENT_USAGE_HISTORY records per agent."""
    agent_stats: dict[str, dict] = {}
    for rec in report.agent_usage:
        stats = agent_stats.setdefault(
            rec.agent_name,
            {
                "total_calls": 0,
                "total_tokens": 0,
                "total_credits": 0.0,
                "total_tool_calls": 0,
                "failures": 0,
                "roles": set(),
            },
        )
        stats["total_calls"] += 1
        stats["total_tokens"] += rec.total_tokens
        stats["total_credits"] += rec.credits_used
        stats["total_tool_calls"] += rec.tool_calls
        if rec.status and rec.status.upper() != "SUCCESS":
            stats["failures"] += 1
        stats["roles"].add(rec.role_name)
    return agent_stats


def _agent_token_and_role_findings(agent_name: str, stats: dict) -> list[GovernanceFinding]:
    """High token usage and multi-role usage for one agent."""
    findings: list[GovernanceFinding] = []
    # High token usage
    if stats["total_tokens"] > 1_000_000:
        findings.append(
            GovernanceFinding(
                category=GovernanceCategory.AGENT_USAGE,
                severity=GovernanceSeverity.MEDIUM,
                title=f"High token usage: {agent_name}",
                description=(
                    f"Agent '{agent_name}' consumed {stats['total_tokens']:,} tokens "
                    f"across {stats['total_calls']} calls "
                    f"({stats['total_credits']:.2f} credits)."
                ),
                agent_or_role=agent_name,
                details={
                    "total_calls": stats["total_calls"],
                    "total_tokens": stats["total_tokens"],
                    "total_credits": stats["total_credits"],
                },
            )
        )

    # Multi-role usage (agent running under multiple roles)
    roles = stats["roles"] - {""}
    if len(roles) > 1:
        findings.append(
            GovernanceFinding(
                category=GovernanceCategory.AGENT_USAGE,
                severity=GovernanceSeverity.HIGH,
                title=f"Multi-role agent: {agent_name}",
                description=(
                    f"Agent '{agent_name}' ran under {len(roles)} different roles: {', '.join(sorted(roles))}. This increases blast radius."
                ),
                agent_or_role=agent_name,
                details={"roles": sorted(roles)},
            )
        )
    return findings


def _agent_tool_and_failure_findings(agent_name: str, stats: dict) -> list[GovernanceFinding]:
    """High tool-call volume and high failure rate for one agent."""
    findings: list[GovernanceFinding] = []
    # High tool call rate
    if stats["total_tool_calls"] > 500:
        findings.append(
            GovernanceFinding(
                category=GovernanceCategory.AGENT_USAGE,
                severity=GovernanceSeverity.MEDIUM,
                title=f"High tool usage: {agent_name}",
                description=(
                    f"Agent '{agent_name}' made {stats['total_tool_calls']} tool calls across {stats['total_calls']} invocations."
                ),
                agent_or_role=agent_name,
                details={
                    "total_tool_calls": stats["total_tool_calls"],
                    "total_calls": stats["total_calls"],
                },
            )
        )

    # High failure rate
    if stats["failures"] > 0 and stats["total_calls"] > 5:
        failure_rate = stats["failures"] / stats["total_calls"]
        if failure_rate > 0.3:
            findings.append(
                GovernanceFinding(
                    category=GovernanceCategory.AGENT_USAGE,
                    severity=GovernanceSeverity.MEDIUM,
                    title=f"High failure rate: {agent_name}",
                    description=(
                        f"Agent '{agent_name}' has a {failure_rate:.0%} failure rate ({stats['failures']}/{stats['total_calls']} calls)."
                    ),
                    agent_or_role=agent_name,
                    details={
                        "failures": stats["failures"],
                        "total_calls": stats["total_calls"],
                        "failure_rate": round(failure_rate, 3),
                    },
                )
            )
    return findings


def _find_agent_usage_anomalies(report: GovernanceReport) -> list[GovernanceFinding]:
    """Analyze CORTEX_AGENT_USAGE_HISTORY for anomalies."""
    findings: list[GovernanceFinding] = []

    if not report.agent_usage:
        return findings

    for agent_name, stats in _aggregate_agent_usage(report).items():
        findings.extend(_agent_token_and_role_findings(agent_name, stats))
        findings.extend(_agent_tool_and_failure_findings(agent_name, stats))

    return findings
