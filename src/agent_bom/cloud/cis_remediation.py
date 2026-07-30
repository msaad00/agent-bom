"""CIS benchmark structured remediation catalog (issue #665).

Every CIS check result gets a ``remediation`` dict on its ``CISCheckResult``
so downstream surfaces (CLI, HTML report, MCP tool JSON, SARIF) can render
actionable, auditable fix guidance alongside the finding.

Schema (all keys always present; values may be empty strings / empty lists /
null for ``fix_cli``):

    why: str                      # 1-sentence risk statement
    fix_cli: str | None           # copy-pasteable command, or None if the
                                  # fix is not safely expressible as a
                                  # single CLI line (e.g. policy review)
    fix_console: str              # UI navigation path
    effort: "low" | "medium" | "high" | "manual"
    priority: int                 # 1 (critical) → 4 (low)
    docs: str                     # CIS / vendor docs URL
    guardrails: list[str]         # tags from GUARDRAIL_TAGS
    requires_human_review: bool   # true when the fix could break prod or
                                  # when the command requires operator
                                  # approval before being applied

Population order (``build_remediation`` walks these in turn):

    1. Hand-authored override keyed by exact cloud, benchmark version, check
       ID, title, and section identity.
    2. Auto-derivation from the result's ``recommendation`` +
       ``severity`` + ``cis_section`` — produces a useful structured form
       even when no override exists.
    3. Universal safe fallback — ``fix_cli=None``, ``effort="manual"``,
       ``requires_human_review=True``, pointing the operator to the
       vendor docs.

Overrides provide control-specific risk and console guidance. CLI mutations
remain absent unless their exact identity is present in the separately reviewed
allowlist; every other check falls back to manual advice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Guardrail principle tags. Kept explicit so the HTML / MCP output can
# filter and group findings by principle (Zero Trust view, Defense in
# Depth view, etc.).
GUARDRAIL_TAGS = {
    "zero-trust",
    "least-privilege",
    "defense-in-depth",
    "segmentation",
    "encryption",
    "logging-and-audit",
    "identity",
    "network-exposure",
    "secrets-handling",
    "skill-guardrail",
    "agent-guardrail",
    "priv-escalation",
    "human-in-loop",
    "availability",
}

# Severity → priority map (1 = critical fix first, 4 = low / advisory).
_SEVERITY_PRIORITY = {
    "critical": 1,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
    "unknown": 3,
    "": 3,
}

# Doc root URLs per cloud. Specific check URLs are built from these by
# ``_docs_url``; checks without a section-specific anchor fall back to the
# root page.
_DOC_ROOTS = {
    "aws": "https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html",
    "azure": "https://learn.microsoft.com/azure/governance/policy/samples/cis-azure-2-0-0",
    "gcp": "https://cloud.google.com/docs/security/cis-benchmarks",
    "snowflake": "https://docs.snowflake.com/en/user-guide/security-cis-benchmark",
}


def _priority_for(severity: str) -> int:
    return _SEVERITY_PRIORITY.get((severity or "").lower(), 3)


def _docs_url(cloud: str, check_id: str) -> str:
    root = _DOC_ROOTS.get(cloud, "")
    return root


def _guardrails_for(cis_section: str, check_id: str) -> list[str]:
    """Infer guardrail principle tags from the CIS section label.

    Sections are free-text in the benchmark files (e.g.
    "1 - Identity and Access Management", "3 - Logging"). The mapping is
    conservative — tags are additive, not exclusive.
    """
    section = (cis_section or "").lower()
    tags: list[str] = []
    if "identity" in section or "access management" in section or "iam" in section:
        tags.extend(["identity", "least-privilege", "priv-escalation"])
    if "logging" in section or "monitor" in section or "audit" in section:
        tags.extend(["logging-and-audit", "defense-in-depth"])
    if "network" in section or "vpc" in section or "firewall" in section:
        tags.extend(["network-exposure", "segmentation"])
    if "storage" in section or "database" in section or "key vault" in section or "kms" in section:
        tags.extend(["encryption", "secrets-handling"])
    if "defender" in section or "security center" in section or "guardduty" in section:
        tags.append("defense-in-depth")
    if "virtual machine" in section or "compute" in section or "app service" in section:
        tags.append("defense-in-depth")

    # Always include zero-trust for IAM / network-facing controls since
    # these are the controls that enforce it.
    if "identity" in section or "network" in section:
        tags.append("zero-trust")

    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for t in tags:
        if t in GUARDRAIL_TAGS and t not in seen:
            out.append(t)
            seen.add(t)
    return out


def _fallback_fix_console(cloud: str, cis_section: str) -> str:
    """Best-effort UI path so operators at least know where to look."""
    section = (cis_section or "").strip()
    if cloud == "aws":
        if "identity" in section.lower():
            return "AWS Console → IAM → Users / Roles"
        if "logging" in section.lower():
            return "AWS Console → CloudTrail → Trails"
        if "s3" in section.lower() or "storage" in section.lower():
            return "AWS Console → S3 → Buckets → Properties"
        return "AWS Console → Security Hub → Controls"
    if cloud == "azure":
        if "identity" in section.lower() or "iam" in section.lower():
            return "Azure Portal → Microsoft Entra ID → Users / Roles"
        if "defender" in section.lower():
            return "Azure Portal → Microsoft Defender for Cloud"
        if "storage" in section.lower():
            return "Azure Portal → Storage accounts → Settings"
        if "key vault" in section.lower():
            return "Azure Portal → Key vaults → Access policies"
        return "Azure Portal → Microsoft Defender for Cloud → Regulatory compliance"
    if cloud == "gcp":
        if "identity" in section.lower() or "iam" in section.lower():
            return "GCP Console → IAM & Admin → IAM"
        if "logging" in section.lower():
            return "GCP Console → Logging → Logs Explorer"
        if "storage" in section.lower():
            return "GCP Console → Cloud Storage → Buckets"
        return "GCP Console → Security Command Center → Findings"
    if cloud == "snowflake":
        return "Snowsight → Admin → Security"
    return ""


def _derived_why(title: str, recommendation: str) -> str:
    """Build a concise 1-sentence risk statement from the existing text."""
    if recommendation:
        # Existing recommendation is already a "do X" sentence. Convert to
        # "failing this check means Y" framing only when it's short; for
        # longer text we keep the title as the risk summary.
        if len(recommendation) <= 140:
            return f"Failure indicates: {title.lower().rstrip('.')}."
    return f"Failure indicates: {title.lower().rstrip('.')}."


# ---------------------------------------------------------------------------
# Hand-authored overrides are bound to an exact benchmark identity. A check ID
# is not stable across benchmark revisions, so matching only ``(cloud,
# check_id)`` can attach a valid command to the wrong control. Unknown,
# incomplete, and drifted identities deliberately fall back to manual advice.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CISControlIdentity:
    cloud: str
    benchmark_version: str
    check_id: str
    title: str
    cis_section: str


@dataclass(frozen=True, slots=True)
class CISRemediationOverride:
    why: str
    fix_console: str
    guardrails: tuple[str, ...]
    fix_cli: str | None = None
    docs: str | None = None
    effort: str = "manual"
    requires_human_review: bool = True


_OVERRIDES: dict[CISControlIdentity, CISRemediationOverride] = {
    # ── AWS ────────────────────────────────────────────────────────────
    CISControlIdentity("aws", "3.0", "1.4", "No root account access keys", "1 - Identity and Access Management"): CISRemediationOverride(
        why="Root account access keys allow full account takeover with no MFA and no per-user audit trail.",
        fix_console=(
            "AWS Organizations → Root access management (preferred for member accounts), or an approved "
            "break-glass root session → IAM → Security credentials → Delete access key → sign out immediately"
        ),
        docs="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_delete-key.html",
        guardrails=("identity", "least-privilege", "priv-escalation", "zero-trust"),
    ),
    CISControlIdentity("aws", "3.0", "1.5", "Root account MFA enabled", "1 - Identity and Access Management"): CISRemediationOverride(
        why="Root user without MFA is a single-password path to full account compromise.",
        fix_console="AWS Console → IAM → Security credentials (root) → Assign MFA device",
        guardrails=("identity", "zero-trust", "priv-escalation", "human-in-loop"),
    ),
    CISControlIdentity("aws", "3.0", "1.6", "Hardware MFA for root account", "1 - Identity and Access Management"): CISRemediationOverride(
        why="Root user without hardware MFA is still usable via phishing or SIM-swap.",
        fix_console="AWS Console → IAM → Security credentials (root) → Assign hardware MFA device",
        guardrails=("identity", "zero-trust", "priv-escalation", "human-in-loop"),
    ),
    CISControlIdentity(
        "aws", "3.0", "1.7", "Root user not used for daily tasks", "1 - Identity and Access Management"
    ): CISRemediationOverride(
        why="Using the root user for daily operations bypasses least-privilege and audit boundaries.",
        fix_console="AWS Console → IAM → Users → create admin user; stop using root for daily ops",
        guardrails=("identity", "least-privilege", "zero-trust"),
    ),
    CISControlIdentity(
        "aws", "3.0", "1.8", "IAM password policy minimum length >= 14", "1 - Identity and Access Management"
    ): CISRemediationOverride(
        why="A weak password policy enables credential stuffing and brute-force against IAM users.",
        fix_console="AWS Console → IAM → Account settings → Password policy",
        guardrails=("identity", "defense-in-depth"),
    ),
    CISControlIdentity(
        "aws", "3.0", "1.14", "Access keys rotated within 90 days", "1 - Identity and Access Management"
    ): CISRemediationOverride(
        why="Access keys older than 90 days increase blast radius of leaked credentials.",
        fix_console="AWS Console → IAM → Users → <user> → Security credentials → Make inactive",
        guardrails=("identity", "least-privilege", "human-in-loop"),
    ),
    CISControlIdentity("aws", "3.0", "2.1.1", "S3 account-level public access block configured", "2 - Storage"): CISRemediationOverride(
        why="Missing account-level Block Public Access permits bucket policies or ACLs to expose data publicly.",
        fix_console="AWS Console → S3 → Block Public Access settings for this account",
        guardrails=("network-exposure", "defense-in-depth"),
    ),
    CISControlIdentity("aws", "3.0", "2.1.2", "S3 bucket server-side encryption enabled", "2 - Storage"): CISRemediationOverride(
        why="Buckets without default server-side encryption can persist new objects without encryption at rest.",
        fix_console="AWS Console → S3 → <bucket> → Properties → Default encryption",
        guardrails=("encryption", "defense-in-depth"),
    ),
    CISControlIdentity("aws", "3.0", "3.1", "CloudTrail enabled in all regions", "3 - Logging"): CISRemediationOverride(
        why="Without a multi-region CloudTrail, API activity can go unlogged in unused regions.",
        fix_console="AWS Console → CloudTrail → Create trail → Apply trail to all regions",
        guardrails=("logging-and-audit", "defense-in-depth"),
    ),
    CISControlIdentity("aws", "3.0", "3.2", "CloudTrail log file validation enabled", "3 - Logging"): CISRemediationOverride(
        why="CloudTrail without log file validation cannot prove log integrity after the fact.",
        fix_console="AWS Console → CloudTrail → Trails → <trail> → Edit → Enable log file validation",
        guardrails=("logging-and-audit", "defense-in-depth"),
    ),
    CISControlIdentity("aws", "3.0", "3.5", "CloudTrail records management events in all regions", "3 - Logging"): CISRemediationOverride(
        why="Excluding management events from CloudTrail leaves control-plane changes unavailable for investigation.",
        fix_console="AWS Console → CloudTrail → Trails → <trail> → Event selectors → Management events",
        guardrails=("logging-and-audit", "defense-in-depth"),
    ),
    # ── Azure ──────────────────────────────────────────────────────────
    CISControlIdentity(
        "azure", "3.0", "3.1", "Secure transfer required on storage accounts", "3 - Storage Accounts"
    ): CISRemediationOverride(
        why="Storage accounts without secure transfer accept plaintext HTTP traffic.",
        fix_console="Azure Portal → Storage accounts → <account> → Configuration → Secure transfer required",
        guardrails=("encryption", "network-exposure"),
    ),
    CISControlIdentity("azure", "3.0", "3.7", "Blob containers set to private access", "3 - Storage Accounts"): CISRemediationOverride(
        why="Public blob access enables unauthenticated data reads over the internet.",
        fix_console="Azure Portal → Storage accounts → <account> → Containers → Change access level to Private",
        guardrails=("network-exposure", "defense-in-depth"),
    ),
    CISControlIdentity(
        "azure", "3.0", "5.1.1", "Diagnostic setting captures Activity Log", "5 - Logging and Monitoring"
    ): CISRemediationOverride(
        why="Missing diagnostic settings prevent centralized capture of control-plane activity.",
        fix_console="Azure Portal → Monitor → Activity log → Export activity logs → Add diagnostic setting",
        guardrails=("logging-and-audit", "defense-in-depth"),
    ),
    CISControlIdentity("azure", "3.0", "8.1", "Expiration date set on Key Vault keys", "8 - Key Vault"): CISRemediationOverride(
        why="Key Vault keys without expiration can remain usable beyond their intended rotation window.",
        fix_console="Azure Portal → Key vaults → <vault> → Keys → <key> → Set expiration",
        guardrails=("encryption", "secrets-handling", "human-in-loop"),
    ),
    # ── GCP ────────────────────────────────────────────────────────────
    CISControlIdentity(
        "gcp", "3.0", "1.4", "No user-managed service account keys", "1 - Identity and Access Management"
    ): CISRemediationOverride(
        why="User-managed service account keys are long-lived credentials that increase exposure when copied or leaked.",
        fix_console="GCP Console → IAM & Admin → Service Accounts → <account> → Keys",
        guardrails=("identity", "least-privilege", "secrets-handling", "human-in-loop"),
    ),
    CISControlIdentity("gcp", "3.0", "2.1", "Cloud Audit Logs configured for all services", "2 - Logging"): CISRemediationOverride(
        why="Without Cloud Audit Logs, sensitive API activity is unavailable for investigations.",
        fix_console="GCP Console → IAM & Admin → Audit Logs → Configure Data Read, Data Write, and Admin Read",
        guardrails=("logging-and-audit", "defense-in-depth"),
    ),
    CISControlIdentity("gcp", "3.0", "3.1", "No default VPC network in the project", "3 - Networking"): CISRemediationOverride(
        why="The default VPC carries broad legacy firewall defaults that weaken environment segmentation.",
        fix_console="GCP Console → VPC network → Review default network and create scoped environment VPCs",
        guardrails=("network-exposure", "segmentation", "zero-trust"),
    ),
    CISControlIdentity("gcp", "3.0", "5.1", "Cloud Storage buckets not publicly accessible", "5 - Cloud Storage"): CISRemediationOverride(
        why="Public allUsers or allAuthenticatedUsers IAM bindings can expose bucket data to the internet.",
        fix_console="GCP Console → Cloud Storage → <bucket> → Permissions → Review public principals",
        guardrails=("network-exposure", "least-privilege"),
    ),
    CISControlIdentity("gcp", "3.0", "5.2", "Uniform bucket-level access enabled on buckets", "5 - Cloud Storage"): CISRemediationOverride(
        why="Buckets without uniform access retain ACL-based authorization paths outside centralized IAM policy.",
        fix_console="GCP Console → Cloud Storage → <bucket> → Permissions → Uniform access control",
        guardrails=("identity", "least-privilege", "defense-in-depth"),
    ),
    # ── Snowflake ──────────────────────────────────────────────────────
    CISControlIdentity(
        "snowflake", "1.0", "1.1", "MFA enabled for password-auth users", "1 - Account and Authentication"
    ): CISRemediationOverride(
        why="Password-authenticated users without MFA remain exposed to single-factor account compromise.",
        fix_console="Snowsight → Admin → Users & Roles → Review MFA enrollment and authentication policy",
        guardrails=("identity", "zero-trust", "human-in-loop"),
    ),
    CISControlIdentity(
        "snowflake", "1.0", "1.2", "Minimum password length 14 or greater", "1 - Account and Authentication"
    ): CISRemediationOverride(
        why="A password policy below 14 characters weakens resistance to password guessing and credential attacks.",
        fix_console="Snowsight → Admin → Security → Password policies",
        guardrails=("identity", "defense-in-depth", "human-in-loop"),
    ),
    CISControlIdentity(
        "snowflake", "1.0", "1.4", "ACCOUNTADMIN granted to at most 2 users", "1 - Account and Authentication"
    ): CISRemediationOverride(
        why="Broad ACCOUNTADMIN assignment weakens separation of duties and expands privileged access.",
        fix_console="Snowsight → Admin → Users & Roles → Review ACCOUNTADMIN grants",
        guardrails=("identity", "least-privilege", "priv-escalation"),
    ),
    CISControlIdentity(
        "snowflake", "1.0", "2.1", "Account-level network policies configured", "2 - Network Security"
    ): CISRemediationOverride(
        why="Without an account network policy, Snowflake access is not restricted to approved network locations.",
        fix_console="Snowsight → Admin → Security → Network policies",
        guardrails=("network-exposure", "segmentation", "zero-trust", "human-in-loop"),
    ),
}

# PR 1 deliberately contains no verified commands. PR 2 may add an identity to
# this set only with provider-doc evidence and exact command-contract tests.
_VERIFIED_CLI_CONTROLS: frozenset[CISControlIdentity] = frozenset()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fail_closed_remediation_payload(value: Any) -> dict[str, Any]:
    """Return a copy safe to expose while the verified CLI set is empty.

    Historical scan jobs and analytics rows can contain commands written by an
    older release. Canonicalizing at projection boundaries prevents those rows
    from replaying stale mutations after an upgrade without rewriting evidence.
    """
    remediation = dict(value) if isinstance(value, dict) else {}
    remediation["fix_cli"] = None
    remediation["effort"] = "manual"
    remediation["requires_human_review"] = True
    return remediation


def build_remediation(
    *,
    cloud: str,
    check_id: str,
    title: str,
    severity: str,
    recommendation: str,
    cis_section: str,
    benchmark_version: str | None = None,
) -> dict[str, Any]:
    """Build a fully-populated remediation dict for a CIS check.

    The caller is typically ``attach_remediation(result, cloud=...)`` but
    this function is pure and testable on its own.
    """
    priority = _priority_for(severity)
    guardrails = _guardrails_for(cis_section, check_id)
    docs = _docs_url(cloud, check_id)
    console = _fallback_fix_console(cloud, cis_section)
    why = _derived_why(title, recommendation)

    base: dict[str, Any] = {
        "why": why,
        "fix_cli": None,
        "fix_console": console,
        "effort": "manual",
        "priority": priority,
        "docs": docs,
        "guardrails": guardrails,
        "requires_human_review": True,
    }

    identity = CISControlIdentity(
        cloud=cloud,
        benchmark_version=benchmark_version or "",
        check_id=check_id,
        title=title,
        cis_section=cis_section,
    )
    override = _OVERRIDES.get(identity)
    if override:
        fix_cli = override.fix_cli if identity in _VERIFIED_CLI_CONTROLS else None
        merged = {
            **base,
            "why": override.why,
            "fix_cli": fix_cli,
            "fix_console": override.fix_console,
            "effort": override.effort if fix_cli else "manual",
            "guardrails": list(override.guardrails),
            "requires_human_review": True,
        }
        if override.docs:
            merged["docs"] = override.docs
        return merged

    return base


def attach_remediation(result: Any, *, cloud: str, benchmark_version: str | None = None) -> None:
    """Populate ``result.remediation`` in-place.

    Idempotent: calling twice produces the same dict. Safe to call on
    ERROR-status results — they still get a remediation pointing the
    operator at the relevant docs.
    """
    result.remediation = build_remediation(
        cloud=cloud,
        check_id=result.check_id,
        title=result.title,
        severity=result.severity,
        recommendation=result.recommendation,
        cis_section=result.cis_section,
        benchmark_version=benchmark_version,
    )


def attach_all(report: Any, *, cloud: str) -> None:
    """Attach remediation to every check in a CIS benchmark report."""
    for check in report.checks:
        attach_remediation(check, cloud=cloud, benchmark_version=getattr(report, "benchmark_version", None))
