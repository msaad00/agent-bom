"""Governance data models for agent access, privilege, and usage analysis.

Used by Snowflake governance discovery and the governance API endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class GovernanceSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GovernanceCategory(str, Enum):
    ACCESS = "access"
    PRIVILEGE = "privilege"
    DATA_CLASSIFICATION = "data_classification"
    AGENT_USAGE = "agent_usage"


@dataclass
class AccessRecord:
    """A single ACCESS_HISTORY entry — who accessed what and how."""

    query_id: str
    user_name: str
    role_name: str
    query_start: str
    object_name: str  # e.g. DB.SCHEMA.TABLE
    object_type: str  # TABLE, VIEW, STAGE, etc.
    columns: list[str] = field(default_factory=list)
    operation: str = ""  # SELECT, INSERT, UPDATE, DELETE
    is_write: bool = False
    base_objects: list[str] = field(default_factory=list)  # underlying objects for views


@dataclass
class PrivilegeGrant:
    """A privilege grant from GRANTS_TO_ROLES or GRANTS_TO_USERS."""

    grantee: str  # role or user name
    grantee_type: str  # "ROLE" or "USER"
    privilege: str  # e.g. "SELECT", "INSERT", "OWNERSHIP", "USAGE"
    granted_on: str  # e.g. "TABLE", "DATABASE", "WAREHOUSE"
    object_name: str  # fully qualified name
    granted_by: str = ""
    grant_option: bool = False
    is_elevated: bool = False  # True for dangerous privs (OWNERSHIP, ALL, CREATE ROLE)


@dataclass
class DataClassification:
    """A TAG_REFERENCES entry — data classification tags on objects."""

    object_name: str
    object_type: str  # TABLE, COLUMN
    column_name: str | None = None
    tag_name: str = ""  # e.g. "PII", "PHI", "FINANCIAL", "CONFIDENTIAL"
    tag_value: str = ""
    tag_database: str = ""
    tag_schema: str = ""


@dataclass
class AgentUsageRecord:
    """A CORTEX_AGENT_USAGE_HISTORY entry — per-call agent telemetry."""

    agent_name: str
    database_name: str = ""
    schema_name: str = ""
    user_name: str = ""
    role_name: str = ""
    start_time: str = ""
    end_time: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    credits_used: float = 0.0
    model_name: str = ""
    tool_calls: int = 0
    status: str = ""  # SUCCESS, FAILED, etc.


@dataclass
class GovernanceFinding:
    """A derived governance risk finding."""

    category: GovernanceCategory
    severity: GovernanceSeverity
    title: str
    description: str
    agent_or_role: str = ""
    object_name: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "agent_or_role": self.agent_or_role,
            "object_name": self.object_name,
            "details": self.details,
        }


@dataclass
class GovernanceReport:
    """Full governance report from Snowflake account analysis."""

    account: str
    access_records: list[AccessRecord] = field(default_factory=list)
    privilege_grants: list[PrivilegeGrant] = field(default_factory=list)
    data_classifications: list[DataClassification] = field(default_factory=list)
    agent_usage: list[AgentUsageRecord] = field(default_factory=list)
    findings: list[GovernanceFinding] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "discovered_at": self.discovered_at,
            "summary": {
                "access_records": len(self.access_records),
                "privilege_grants": len(self.privilege_grants),
                "data_classifications": len(self.data_classifications),
                "agent_usage_records": len(self.agent_usage),
                "findings": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f.severity == GovernanceSeverity.CRITICAL),
                "high_findings": sum(1 for f in self.findings if f.severity == GovernanceSeverity.HIGH),
            },
            "findings": [f.to_dict() for f in self.findings],
            "access_records": [
                {
                    "query_id": r.query_id,
                    "user_name": r.user_name,
                    "role_name": r.role_name,
                    "query_start": r.query_start,
                    "object_name": r.object_name,
                    "object_type": r.object_type,
                    "columns": r.columns,
                    "operation": r.operation,
                    "is_write": r.is_write,
                }
                for r in self.access_records
            ],
            "privilege_grants": [
                {
                    "grantee": g.grantee,
                    "grantee_type": g.grantee_type,
                    "privilege": g.privilege,
                    "granted_on": g.granted_on,
                    "object_name": g.object_name,
                    "is_elevated": g.is_elevated,
                }
                for g in self.privilege_grants
            ],
            "data_classifications": [
                {
                    "object_name": d.object_name,
                    "object_type": d.object_type,
                    "column_name": d.column_name,
                    "tag_name": d.tag_name,
                    "tag_value": d.tag_value,
                }
                for d in self.data_classifications
            ],
            "agent_usage": [
                {
                    "agent_name": u.agent_name,
                    "user_name": u.user_name,
                    "role_name": u.role_name,
                    "start_time": u.start_time,
                    "total_tokens": u.total_tokens,
                    "credits_used": u.credits_used,
                    "model_name": u.model_name,
                    "tool_calls": u.tool_calls,
                    "status": u.status,
                }
                for u in self.agent_usage
            ],
            "warnings": self.warnings,
        }
