"""Advisory remediation foundation — per-finding fix + least-privilege + artifact.

agent-bom NEVER needs write or remediation permissions. This module DETECTS the
exact fix for a finding and RECOMMENDS it; the user (or their own automation)
applies it on their own terms. Nothing here executes, writes, or requests
elevated access. Auto-remediation, if ever, is opt-in and separately scoped via
the side-scan contract — declining a permission degrades to recommendation,
never blocks.

``build_remediation(finding) -> Remediation`` returns a structured advisory:

    fix                — the exact action: CLI command / console steps /
                         Terraform or policy diff / IaC patch.
    required_privilege — the precise least-privilege the USER needs to APPLY
                         the fix, phrased so they scope it on their own apply
                         role. agent-bom never requests it.
    artifact           — optional generated, reviewable text (Terraform
                         snippet / runbook / PR body) the user applies
                         themselves. Generated, NOT applied.

Everything is marked advisory (``applied=False``, ``auto_remediation=False``).
The function is pure and deterministic: no network, no filesystem, no execution.

This is the FOUNDATION. CIS findings are populated here as the reference
pattern; per-scanner fix population for other finding types is follow-up work.
A finding with no rich fix data still returns a non-empty recommendation —
guidance is never dropped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from agent_bom.core.severity import severity_fix_priority
from agent_bom.remediation_model import REMEDIATION_SCHEMA_VERSION as REMEDIATION_SCHEMA_VERSION
from agent_bom.remediation_model import Remediation as Remediation
from agent_bom.remediation_model import RemediationArtifact as RemediationArtifact
from agent_bom.remediation_model import RemediationFix as RemediationFix
from agent_bom.remediation_model import RequiredPrivilege as RequiredPrivilege

if TYPE_CHECKING:
    from agent_bom.finding import Finding


# ---------------------------------------------------------------------------
# Least-privilege derivation (CIS reference pattern)
# ---------------------------------------------------------------------------

# Maps a provider + CLI verb prefix to the concrete permission the operator
# must grant to their OWN apply role. Conservative: only verbs we can name
# precisely. Anything unmatched degrades to a console-review privilege note.
_PROVIDER_APPLY_NOTE: dict[str, str] = {
    "aws": "grant these IAM actions to your own apply role (least-privilege, not agent-bom)",
    "azure": "grant a custom Azure RBAC role with these actions to your own apply identity",
    "gcp": "grant these IAM permissions to your own apply service account",
    "snowflake": "run as a role that holds these privileges (e.g. SECURITYADMIN/ACCOUNTADMIN), scoped to the object",
}

# CLI command stem -> least-privilege action(s) the operator needs to APPLY it.
_CLI_ACTION_HINTS: tuple[tuple[str, list[str]], ...] = (
    ("aws iam delete-access-key", ["iam:DeleteAccessKey"]),
    ("aws iam update-access-key", ["iam:UpdateAccessKey"]),
    ("aws iam update-account-password-policy", ["iam:UpdateAccountPasswordPolicy"]),
    ("aws s3api put-public-access-block", ["s3:PutBucketPublicAccessBlock"]),
    ("aws s3control put-public-access-block", ["s3:PutAccountPublicAccessBlock"]),
    ("aws cloudtrail create-trail", ["cloudtrail:CreateTrail", "cloudtrail:StartLogging"]),
    ("aws cloudtrail update-trail", ["cloudtrail:UpdateTrail"]),
    ("aws cloudtrail start-logging", ["cloudtrail:StartLogging"]),
    ("aws kms enable-key-rotation", ["kms:EnableKeyRotation"]),
    ("az security pricing", ["Microsoft.Security/pricings/write"]),
    ("az storage account update", ["Microsoft.Storage/storageAccounts/write"]),
    ("gcloud iam service-accounts keys delete", ["iam.serviceAccountKeys.delete"]),
    ("gcloud storage buckets update", ["storage.buckets.update"]),
    ("gsutil iam ch", ["storage.buckets.setIamPolicy"]),
    ("create network policy", ["CREATE NETWORK POLICY", "ALTER ACCOUNT"]),
    ("alter user", ["OWNERSHIP or MANAGE GRANTS on the user"]),
)


def _provider_from_finding(finding: "Finding") -> str:
    """Best-effort cloud provider from CIS finding evidence."""
    evidence = finding.evidence or {}
    provider = str(evidence.get("provider", "") or "").lower()
    if provider:
        return provider
    location = (finding.asset.location or "").lower()
    for known in ("aws", "azure", "gcp", "snowflake"):
        if known in location:
            return known
    return ""


def _actions_for_cli(cli: Optional[str]) -> list[str]:
    """Derive least-privilege actions from a known CLI stem. Deterministic."""
    if not cli:
        return []
    lowered = cli.lower()
    for stem, actions in _CLI_ACTION_HINTS:
        if stem in lowered:
            return list(actions)
    return []


def _required_privilege_for_cis(
    finding: "Finding",
    provider: str,
    cli: Optional[str],
) -> RequiredPrivilege:
    """Build the least-privilege note the USER needs to APPLY a CIS fix."""
    actions = _actions_for_cli(cli)
    note = _PROVIDER_APPLY_NOTE.get(provider, "grant the minimum permission to your own apply role")
    if actions:
        description = f"To apply this fix: {note}."
        scope = "Scope to the affected resource(s) only; agent-bom remains read-only and requests nothing."
    else:
        description = (
            "To apply this fix: review the documented control and grant your own apply "
            "role the minimum permission for the affected resource."
        )
        scope = "agent-bom never requests this privilege — you scope and hold it on your terms."
    return RequiredPrivilege(description=description, actions=actions, scope_note=scope)


def _runbook_artifact_for_cis(
    finding: "Finding",
    provider: str,
    fix: RemediationFix,
    privilege: RequiredPrivilege,
) -> RemediationArtifact:
    """Generate a reviewable remediation runbook as text. Never written to disk."""
    check_id = str((finding.evidence or {}).get("check_id", "") or "")
    lines: list[str] = [
        f"# Remediation runbook: {finding.title}".rstrip(),
        "",
        "> Advisory only. agent-bom recommends; you review and apply. Read-only forever.",
        "",
        f"- Provider: {provider or 'unknown'}",
    ]
    if check_id:
        lines.append(f"- Control: {check_id}")
    lines.append(f"- Severity: {finding.effective_severity()}")
    if fix.summary:
        lines += ["", "## Fix", fix.summary]
    if fix.cli:
        lines += ["", "```bash", fix.cli, "```"]
    if fix.console:
        lines += ["", f"Console: {fix.console}"]
    if fix.diff:
        lines += ["", "## Patch (review before applying)", "```", fix.diff, "```"]
    lines += ["", "## Least-privilege to apply", privilege.description]
    if privilege.actions:
        lines += ["", "Required actions (grant to YOUR apply role):"]
        lines += [f"- {action}" for action in privilege.actions]
    if privilege.scope_note:
        lines += ["", privilege.scope_note]
    if fix.docs:
        lines += ["", f"Docs: {fix.docs}"]
    return RemediationArtifact(
        kind="runbook",
        filename=f"remediation-{check_id or 'finding'}.md",
        content="\n".join(lines) + "\n",
    )


def _priority_for(severity: str) -> int:
    return severity_fix_priority(severity)


def _build_cis_remediation(finding: "Finding") -> Remediation:
    """Reference pattern: structured advisory for a CIS finding.

    Reuses the cloud CIS remediation catalog (``fix_cli`` / ``fix_console`` /
    ``why`` / ``guardrails`` / ``effort``) where present, and layers on the
    least-privilege-to-apply note + a generated runbook artifact. Pure: the
    catalog lookup is in-memory and deterministic.
    """
    from agent_bom.cloud.cis_remediation import build_remediation as build_cis_catalog

    evidence = finding.evidence or {}
    provider = _provider_from_finding(finding)
    check_id = str(evidence.get("check_id", "") or "")
    control_title = str(evidence.get("control_title", "") or finding.title)
    cis_section = str(evidence.get("cis_section", "") or "")
    benchmark_version = str(evidence.get("benchmark_version", "") or "") or None
    recommendation = finding.remediation_guidance or ""

    catalog = build_cis_catalog(
        cloud=provider,
        check_id=check_id,
        title=control_title,
        severity=finding.effective_severity(),
        recommendation=recommendation,
        cis_section=cis_section,
        benchmark_version=benchmark_version,
    )

    # The check's own remediation block wins where present — it was produced for
    # this resource, where the catalog entry is generic to the control id.
    own_fix = evidence.get("remediation_fix")
    own_fix = own_fix if isinstance(own_fix, dict) else {}
    cli = own_fix.get("fix_cli") or catalog.get("fix_cli")
    console = own_fix.get("fix_console") or catalog.get("fix_console") or None
    summary = recommendation or str(catalog.get("why") or "") or finding.title
    fix = RemediationFix(
        summary=summary,
        cli=cli if isinstance(cli, str) else None,
        console=console if isinstance(console, str) else None,
        diff=None,
        docs=str(catalog.get("docs") or "") or None,
        requires_human_review=bool(own_fix.get("requires_human_review", catalog.get("requires_human_review", True))),
    )

    privilege = _required_privilege_for_cis(finding, provider, fix.cli)
    artifact = _runbook_artifact_for_cis(finding, provider, fix, privilege)
    guardrails = [str(g) for g in (own_fix.get("guardrails") or catalog.get("guardrails") or [])]
    effort = str(own_fix.get("effort") or catalog.get("effort") or "manual")
    priority = int(own_fix.get("priority") or catalog.get("priority") or _priority_for(finding.effective_severity()))

    return Remediation(
        fix=fix,
        required_privilege=privilege,
        artifact=artifact,
        effort=effort,
        priority=priority,
        guardrails=guardrails,
        applied=False,
        auto_remediation=False,
    )


def _degraded_recommendation(finding: "Finding") -> Remediation:
    """Fallback advisory for findings without rich fix data.

    Guidance is never empty: at minimum we restate the finding's own
    remediation guidance (or a conservative review instruction) and the
    least-privilege framing. No CLI, no artifact — but a usable recommendation.
    """
    summary = finding.remediation_guidance or (
        "Review the finding and apply the vendor-recommended mitigation, upgrade path, or compensating control."
    )
    fix = RemediationFix(summary=summary, requires_human_review=True)
    privilege = RequiredPrivilege(
        description=(
            "To apply any fix: grant your own apply role the minimum permission for the affected resource. agent-bom never requests it."
        ),
        scope_note="agent-bom is read-only; it recommends, you apply on your terms.",
    )
    return Remediation(
        fix=fix,
        required_privilege=privilege,
        artifact=None,
        effort="manual",
        priority=_priority_for(finding.effective_severity()),
        applied=False,
        auto_remediation=False,
    )


def build_remediation(finding: "Finding") -> Remediation:
    """Return a structured, advisory remediation for a finding.

    Pure and deterministic: no network, no filesystem, no execution. The
    returned ``Remediation`` is always advisory (``applied=False``,
    ``auto_remediation=False``). CIS findings get the full reference treatment
    (fix + least-privilege + runbook artifact); every other finding degrades to
    a non-empty recommendation — guidance is never dropped.
    """
    from agent_bom.finding import FindingType

    if finding.finding_type == FindingType.CIS_FAIL:
        return _build_cis_remediation(finding)
    return _degraded_recommendation(finding)
