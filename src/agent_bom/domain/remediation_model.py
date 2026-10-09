"""Advisory remediation record types attached to a ``Finding``.

Kept apart from :mod:`agent_bom.remediation`, which builds them from findings,
so the finding model can name these types without a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

REMEDIATION_SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class RemediationFix:
    """The exact action the user can apply. All fields optional/advisory.

    At least one of ``cli`` / ``console`` / ``diff`` / ``summary`` is always
    populated so a fix is never an empty recommendation. ``diff`` carries a
    Terraform/policy/IaC patch as reviewable text.
    """

    summary: str = ""  # one-line "do X" statement
    cli: Optional[str] = None  # copy-pasteable command, or None when unsafe as one line
    console: Optional[str] = None  # UI navigation path
    diff: Optional[str] = None  # Terraform / policy / IaC patch as text
    docs: Optional[str] = None  # vendor / benchmark documentation URL
    requires_human_review: bool = True  # operator must review before applying

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "cli": self.cli,
            "console": self.console,
            "diff": self.diff,
            "docs": self.docs,
            "requires_human_review": self.requires_human_review,
        }


@dataclass(frozen=True)
class RequiredPrivilege:
    """The least-privilege the USER needs to APPLY the fix.

    agent-bom never requests this — it tells the operator exactly what to grant
    to *their own* apply role so they keep the scope on their terms. ``actions``
    is the concrete permission list (IAM actions, SQL grants, RBAC roles).
    """

    description: str = ""  # human phrasing, e.g. "to apply: grant to your apply role"
    actions: list[str] = field(default_factory=list)  # e.g. ["ec2:ModifyInstanceAttribute"]
    scope_note: str = ""  # how to bound it, e.g. "scope to the affected resource only"

    def to_dict(self) -> dict[str, object]:
        return {
            "description": self.description,
            "actions": list(self.actions),
            "scope_note": self.scope_note,
        }


@dataclass(frozen=True)
class RemediationArtifact:
    """A generated, reviewable artifact the user applies themselves.

    Generated as TEXT only — never written to disk or applied by agent-bom.
    ``kind`` is one of "terraform" | "runbook" | "pr_body" | "policy".
    """

    kind: str
    filename: str  # suggested name if the user chooses to save it themselves
    content: str  # the artifact body, as text

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "filename": self.filename,
            "content": self.content,
        }


@dataclass(frozen=True)
class Remediation:
    """Structured advisory for a single finding. Read-only forever.

    ``applied`` and ``auto_remediation`` are always False: agent-bom recommends,
    the user applies. ``effort`` mirrors the CIS catalog vocabulary
    ("low" | "medium" | "high" | "manual").
    """

    fix: RemediationFix
    required_privilege: RequiredPrivilege
    artifact: Optional[RemediationArtifact] = None
    effort: str = "manual"
    priority: int = 3  # 1 (critical) -> 4 (low)
    guardrails: list[str] = field(default_factory=list)
    applied: bool = False  # advisory: agent-bom never applies
    auto_remediation: bool = False  # advisory: opt-in + separately scoped if ever

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": REMEDIATION_SCHEMA_VERSION,
            "fix": self.fix.to_dict(),
            "required_privilege": self.required_privilege.to_dict(),
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "effort": self.effort,
            "priority": self.priority,
            "guardrails": list(self.guardrails),
            "applied": self.applied,
            "auto_remediation": self.auto_remediation,
        }
