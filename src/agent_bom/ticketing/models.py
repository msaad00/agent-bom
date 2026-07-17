"""Provider-neutral ticketing data model.

These types are the contract every transport (MCP-client or direct-REST) speaks,
so the service, MCP tools, and REST route never depend on a vendor shape. A
:class:`TicketingConnectionRecord` is the stored, encrypted, tenant-scoped
connection through which every action runs — its ``secret_encrypted`` column is
the only sensitive field and is never returned by the API.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

# ── Vocabulary ────────────────────────────────────────────────────────────────

PROVIDER_JIRA = "jira"
PROVIDER_SERVICENOW = "servicenow"
PROVIDER_GENERIC = "generic"
SUPPORTED_TICKETING_PROVIDERS: tuple[str, ...] = (PROVIDER_JIRA, PROVIDER_SERVICENOW, PROVIDER_GENERIC)

# How a connection reaches its ITSM.
TRANSPORT_MCP = "mcp"  # agent-bom is an MCP client of an ITSM MCP server (primary)
TRANSPORT_REST = "rest"  # direct per-vendor REST adapter (fallback)
SUPPORTED_TRANSPORTS: tuple[str, ...] = (TRANSPORT_MCP, TRANSPORT_REST)

# How the stored secret authenticates. All are entered once at connect time and
# sealed at rest; none is ever re-entered per action.
AUTH_OAUTH = "oauth"  # OAuth 2.0 (3LO) bearer + refresh bundle (primary for Jira Cloud)
AUTH_API_TOKEN = "api_token"  # secondary fallback: a scoped API token, sealed once
AUTH_MCP = "mcp"  # the MCP server's own auth (bearer), sealed once
SUPPORTED_AUTH_METHODS: tuple[str, ...] = (AUTH_OAUTH, AUTH_API_TOKEN, AUTH_MCP)

# Connection lifecycle status.
STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_ERROR = "error"


class TicketStatus(str, Enum):
    """Canonical, provider-neutral ticket status.

    Every transport maps its vendor status into one of these so the finding's
    status chip and the API/MCP surface stay vendor-independent.
    """

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    UNKNOWN = "unknown"


# Severity → a generic priority label transports can remap to their own scheme.
SEVERITY_PRIORITY: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "Lowest",
    "info": "Lowest",
}


@dataclass(frozen=True)
class TicketDraft:
    """Normalized ticket content derived from a finding/issue.

    Transport-neutral: the MCP transport passes these fields as tool arguments and
    the REST transport renders them into the vendor body. It never carries a
    credential or base URL — those live only in the stored connection.
    """

    finding_id: str
    project: str
    title: str
    description: str
    severity: str = "medium"
    issue_type: str = ""
    labels: tuple[str, ...] = ()
    source_url: str = ""

    @property
    def priority(self) -> str:
        return SEVERITY_PRIORITY.get((self.severity or "").strip().lower(), "Medium")

    def to_arguments(self) -> dict[str, Any]:
        """Argument dict for an MCP ITSM tool (stable, vendor-neutral keys)."""
        return {
            "project": self.project,
            "summary": self.title,
            "description": self.description,
            "severity": (self.severity or "").strip().lower(),
            "priority": self.priority,
            "issue_type": self.issue_type or "Bug",
            "labels": list(self.labels),
            "finding_id": self.finding_id,
            "source_url": self.source_url,
        }

    @classmethod
    def from_finding(
        cls,
        finding: dict[str, Any],
        *,
        project: str,
        finding_id: str = "",
        issue_type: str = "",
        source_url: str = "",
    ) -> TicketDraft:
        """Build a normalized draft from an agent-bom finding/blast-radius dict."""
        fid = (finding_id or _finding_id(finding)).strip()
        severity = str(finding.get("severity") or "medium").strip().lower()
        vuln = str(finding.get("vulnerability_id") or finding.get("cve") or finding.get("id") or "finding").strip()
        package = str(finding.get("package") or finding.get("component") or "").strip()
        risk = finding.get("risk_score")
        title_pkg = f" in {package}" if package else ""
        if isinstance(risk, (int, float)):
            title = f"[agent-bom] {vuln}{title_pkg} (risk {float(risk):.1f}/10)"
        else:
            title = f"[agent-bom] {vuln}{title_pkg}"
        description = _describe(finding, vuln=vuln, package=package, severity=severity)
        labels = ["agent-bom", "security", f"severity-{severity}"]
        return cls(
            finding_id=fid,
            project=project.strip(),
            title=title[:255],
            description=description,
            severity=severity,
            issue_type=issue_type,
            labels=tuple(labels),
            source_url=source_url.strip(),
        )


def _finding_id(finding: dict[str, Any]) -> str:
    """Stable identifier for dedupe when the caller does not pass one.

    Prefers an explicit id; otherwise a deterministic composite of the
    vulnerability + package so re-filing the same finding dedupes.
    """
    for key in ("finding_id", "id", "vulnerability_id", "cve"):
        value = str(finding.get(key) or "").strip()
        if value:
            package = str(finding.get("package") or finding.get("component") or "").strip()
            return f"{value}:{package}" if package else value
    return ""


def _describe(finding: dict[str, Any], *, vuln: str, package: str, severity: str) -> str:
    parts = [
        f"Vulnerability: {vuln}",
        f"Package: {package}" if package else "",
        f"Severity: {severity}",
    ]
    risk = finding.get("risk_score")
    if isinstance(risk, (int, float)):
        parts.append(f"Risk score: {float(risk):.1f}/10")
    fix = str(finding.get("fixed_version") or "").strip()
    if fix:
        parts.append(f"Fix: upgrade to {fix}")
    for label, key in (("Affected agents", "affected_agents"), ("Affected servers", "affected_servers")):
        values = finding.get(key)
        if isinstance(values, (list, tuple)) and values:
            parts.append(f"{label}: {', '.join(str(v) for v in values)}")
    return "\n".join(p for p in parts if p)


@dataclass(frozen=True)
class TicketRef:
    """A created ticket's provider-side reference + human handle + deep link."""

    provider: str
    external_id: str  # Jira issue id / ServiceNow sys_id / MCP-returned id
    key: str = ""  # human handle: Jira key (SEC-123) / ServiceNow number (INC0012)
    url: str = ""  # deep link to the ticket
    status: TicketStatus = TicketStatus.OPEN

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "external_id": self.external_id,
            "key": self.key,
            "url": self.url,
            "status": self.status.value,
        }


@dataclass
class TicketingConnectionRecord:
    """One stored, encrypted, tenant-scoped ITSM connection (connect-once).

    ``secret_encrypted`` is the Fernet ciphertext of the auth bundle — an OAuth
    token bundle (access/refresh), an API token, or an MCP-server bearer — and is
    the only sensitive column. :meth:`to_public_dict` never emits it.
    ``auth_params`` holds non-secret connection params (Jira cloud id / default
    project / email; the MCP tool names) and is safe to return.
    """

    id: str
    tenant_id: str
    provider: str  # jira | servicenow | generic
    transport: str  # mcp | rest
    auth_method: str  # oauth | api_token | mcp
    display_name: str
    endpoint: str  # REST base URL, or the ITSM MCP server URL
    secret_encrypted: str
    auth_params: dict[str, str] = field(default_factory=dict)
    status: str = STATUS_PENDING
    status_detail: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("secret_encrypted", None)
        data["has_secret"] = bool(self.secret_encrypted)
        return data
