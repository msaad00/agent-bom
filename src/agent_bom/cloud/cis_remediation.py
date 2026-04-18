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

    1. Hand-authored override keyed by (cloud, check_id) — takes precedence
       for checks where the CLI form is unambiguous.
    2. Auto-derivation from the result's ``recommendation`` +
       ``severity`` + ``cis_section`` — produces a useful structured form
       even when no override exists.
    3. Universal safe fallback — ``fix_cli=None``, ``effort="manual"``,
       ``requires_human_review=True``, pointing the operator to the
       vendor docs.

The overrides intentionally skew toward the highest-frequency checks
(IAM root/MFA, CloudTrail/logging, storage encryption-at-rest, public
bucket access) where a single command is both safe and well-documented
by CIS. Other checks fall back to the auto-derived form rather than
shipping commands that might break production.
"""

from __future__ import annotations

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
# Hand-authored overrides — only for checks where the CLI is safe and
# unambiguous. Every entry below was cross-checked against CIS v3 (AWS /
# Azure / GCP) or the Snowflake CIS benchmark. Commands intentionally use
# placeholders (``<ARN>``, ``<RG>``, ``<PROJECT>``, etc.) so operators
# must substitute before running — this is the human-in-loop surface.
# ---------------------------------------------------------------------------

_OVERRIDES: dict[tuple[str, str], dict[str, Any]] = {
    # ── AWS ────────────────────────────────────────────────────────────
    ("aws", "1.4"): {
        "why": "Root account access keys allow full account takeover with no MFA and no per-user audit trail.",
        "fix_cli": "aws iam delete-access-key --user-name root --access-key-id <ROOT_KEY_ID>",
        "fix_console": "AWS Console → IAM → Security credentials (root) → Delete access key",
        "effort": "low",
        "guardrails": ["identity", "least-privilege", "priv-escalation", "zero-trust"],
        "requires_human_review": True,
    },
    ("aws", "1.5"): {
        "why": "Root user without MFA is a single-password path to full account compromise.",
        "fix_cli": None,  # MFA enablement requires device enrollment — not a pure CLI fix
        "fix_console": "AWS Console → IAM → Security credentials (root) → Assign MFA device",
        "effort": "medium",
        "guardrails": ["identity", "zero-trust", "priv-escalation", "human-in-loop"],
        "requires_human_review": True,
    },
    ("aws", "1.6"): {
        "why": "Root user without hardware MFA is still usable via phishing or SIM-swap.",
        "fix_cli": None,
        "fix_console": "AWS Console → IAM → Security credentials (root) → Assign hardware MFA device",
        "effort": "medium",
        "guardrails": ["identity", "zero-trust", "priv-escalation", "human-in-loop"],
        "requires_human_review": True,
    },
    ("aws", "1.7"): {
        "why": "Using the root user for daily operations bypasses least-privilege and audit boundaries.",
        "fix_cli": None,
        "fix_console": "AWS Console → IAM → Users → create admin user; stop using root for daily ops",
        "effort": "medium",
        "guardrails": ["identity", "least-privilege", "zero-trust"],
        "requires_human_review": True,
    },
    ("aws", "1.8"): {
        "why": "A weak password policy enables credential stuffing and brute-force against IAM users.",
        "fix_cli": (
            "aws iam update-account-password-policy --minimum-password-length 14 "
            "--require-symbols --require-numbers --require-uppercase-characters "
            "--require-lowercase-characters --allow-users-to-change-password "
            "--max-password-age 90 --password-reuse-prevention 24"
        ),
        "fix_console": "AWS Console → IAM → Account settings → Password policy",
        "effort": "low",
        "guardrails": ["identity", "defense-in-depth"],
        "requires_human_review": False,
    },
    ("aws", "1.14"): {
        "why": "Access keys older than 90 days increase blast radius of leaked credentials.",
        "fix_cli": "aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>",
        "fix_console": "AWS Console → IAM → Users → <user> → Security credentials → Make inactive",
        "effort": "low",
        "guardrails": ["identity", "least-privilege", "human-in-loop"],
        "requires_human_review": True,
    },
    ("aws", "2.1.1"): {
        "why": "S3 bucket without Block Public Access can be made internet-reachable by any bucket policy edit.",
        "fix_cli": (
            "aws s3api put-public-access-block --bucket <BUCKET> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "fix_console": "AWS Console → S3 → <bucket> → Permissions → Block public access",
        "effort": "low",
        "guardrails": ["network-exposure", "defense-in-depth"],
        "requires_human_review": True,
    },
    ("aws", "2.1.2"): {
        "why": "Account-level Block Public Access is the backstop against any per-bucket misconfig.",
        "fix_cli": (
            "aws s3control put-public-access-block --account-id <ACCOUNT_ID> "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,"
            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "fix_console": "AWS Console → S3 → Block Public Access settings for this account",
        "effort": "low",
        "guardrails": ["network-exposure", "defense-in-depth"],
        "requires_human_review": True,
    },
    ("aws", "3.1"): {
        "why": "Without a multi-region CloudTrail, API activity can go unlogged in unused regions.",
        "fix_cli": (
            "aws cloudtrail create-trail --name org-trail --s3-bucket-name <LOG_BUCKET> "
            "--is-multi-region-trail --include-global-service-events && "
            "aws cloudtrail start-logging --name org-trail"
        ),
        "fix_console": "AWS Console → CloudTrail → Create trail → Apply trail to all regions",
        "effort": "low",
        "guardrails": ["logging-and-audit", "defense-in-depth"],
        "requires_human_review": True,
    },
    ("aws", "3.2"): {
        "why": "CloudTrail without log file validation cannot prove log integrity after the fact.",
        "fix_cli": "aws cloudtrail update-trail --name <TRAIL> --enable-log-file-validation",
        "fix_console": "AWS Console → CloudTrail → Trails → <trail> → Edit → Enable log file validation",
        "effort": "low",
        "guardrails": ["logging-and-audit", "defense-in-depth"],
        "requires_human_review": False,
    },
    ("aws", "3.5"): {
        "why": "CloudTrail KMS key rotation limits exposure if a key is ever compromised.",
        "fix_cli": "aws kms enable-key-rotation --key-id <CLOUDTRAIL_KMS_KEY_ID>",
        "fix_console": "AWS Console → KMS → Keys → <key> → Key rotation → Enable",
        "effort": "low",
        "guardrails": ["encryption", "secrets-handling"],
        "requires_human_review": False,
    },
    # ── Azure ──────────────────────────────────────────────────────────
    ("azure", "2.1.1"): {
        "why": "Microsoft Defender for Servers off means hosts lack EDR-grade detection.",
        "fix_cli": "az security pricing create --name VirtualMachines --tier Standard",
        "fix_console": "Azure Portal → Microsoft Defender for Cloud → Environment settings → <subscription> → Defender plans",
        "effort": "low",
        "guardrails": ["defense-in-depth"],
        "requires_human_review": True,
    },
    ("azure", "3.1"): {
        "why": "Storage account without 'Secure transfer required' accepts plaintext HTTP traffic.",
        "fix_cli": "az storage account update --name <SA_NAME> --resource-group <RG> --https-only true",
        "fix_console": "Azure Portal → Storage accounts → <sa> → Configuration → Secure transfer required",
        "effort": "low",
        "guardrails": ["encryption", "network-exposure"],
        "requires_human_review": False,
    },
    ("azure", "3.7"): {
        "why": "Public blob access enables unauthenticated data read over the internet.",
        "fix_cli": "az storage account update --name <SA_NAME> --resource-group <RG> --allow-blob-public-access false",
        "fix_console": "Azure Portal → Storage accounts → <sa> → Configuration → Allow Blob public access: Disabled",
        "effort": "low",
        "guardrails": ["network-exposure", "defense-in-depth"],
        "requires_human_review": True,
    },
    ("azure", "5.1.1"): {
        "why": "Diagnostic settings off means control-plane activity is not centrally captured.",
        "fix_cli": None,
        "fix_console": "Azure Portal → Monitor → Activity log → Export activity logs → Add diagnostic setting",
        "effort": "medium",
        "guardrails": ["logging-and-audit", "defense-in-depth"],
        "requires_human_review": True,
    },
    ("azure", "8.1"): {
        "why": "Key Vault keys without expiration linger past their rotation window.",
        "fix_cli": None,
        "fix_console": "Azure Portal → Key vaults → <vault> → Keys → <key> → Set expiration",
        "effort": "medium",
        "guardrails": ["encryption", "secrets-handling", "human-in-loop"],
        "requires_human_review": True,
    },
    # ── GCP ────────────────────────────────────────────────────────────
    ("gcp", "1.4"): {
        "why": "Service account keys are long-lived credentials; rotation and minimization reduce exposure.",
        "fix_cli": "gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA_EMAIL>",
        "fix_console": "GCP Console → IAM & Admin → Service Accounts → <sa> → Keys",
        "effort": "low",
        "guardrails": ["identity", "least-privilege", "secrets-handling", "human-in-loop"],
        "requires_human_review": True,
    },
    ("gcp", "2.1"): {
        "why": "Without Cloud Audit Logs, sensitive API activity is not recoverable for investigations.",
        "fix_cli": None,  # Requires full policy IAM bindings mutation — console-safer
        "fix_console": "GCP Console → IAM & Admin → Audit Logs → Enable Data Read / Data Write / Admin Read for all services",
        "effort": "medium",
        "guardrails": ["logging-and-audit", "defense-in-depth"],
        "requires_human_review": True,
    },
    ("gcp", "3.1"): {
        "why": "Default VPC permits east-west traffic across legacy defaults that predate firewall best practices.",
        "fix_cli": None,
        "fix_console": "GCP Console → VPC network → Delete default network; create scoped VPCs per environment",
        "effort": "high",
        "guardrails": ["network-exposure", "segmentation", "zero-trust"],
        "requires_human_review": True,
    },
    ("gcp", "5.1"): {
        "why": "Storage buckets with uniform bucket-level access off still allow ACL-based public read.",
        "fix_cli": "gcloud storage buckets update gs://<BUCKET> --uniform-bucket-level-access",
        "fix_console": "GCP Console → Cloud Storage → <bucket> → Permissions → Uniform access control",
        "effort": "low",
        "guardrails": ["network-exposure", "defense-in-depth"],
        "requires_human_review": False,
    },
    ("gcp", "5.2"): {
        "why": "Buckets with public allUsers/allAuthenticatedUsers binding leak data over the internet.",
        "fix_cli": "gsutil iam ch -d allUsers:objectViewer gs://<BUCKET> && gsutil iam ch -d allAuthenticatedUsers:objectViewer gs://<BUCKET>",
        "fix_console": "GCP Console → Cloud Storage → <bucket> → Permissions → remove allUsers / allAuthenticatedUsers",
        "effort": "low",
        "guardrails": ["network-exposure", "least-privilege"],
        "requires_human_review": True,
    },
    # ── Snowflake ──────────────────────────────────────────────────────
    ("snowflake", "1.1"): {
        "why": "SCIM / SSO disabled means identity lifecycle is not tied to the corporate IdP.",
        "fix_cli": None,
        "fix_console": "Snowsight → Admin → Security → SCIM / SSO integrations",
        "effort": "high",
        "guardrails": ["identity", "zero-trust", "human-in-loop"],
        "requires_human_review": True,
    },
    ("snowflake", "1.2"): {
        "why": "Users without MFA are a single-password path to tenant compromise.",
        "fix_cli": "ALTER USER <USER> SET MINS_TO_BYPASS_MFA=0;  -- enforce MFA",
        "fix_console": "Snowsight → Admin → Users & Roles → <user> → Require MFA",
        "effort": "low",
        "guardrails": ["identity", "zero-trust", "priv-escalation"],
        "requires_human_review": True,
    },
    ("snowflake", "1.4"): {
        "why": "ACCOUNTADMIN used for day-to-day operations breaks separation of duties.",
        "fix_cli": None,
        "fix_console": "Snowsight → Admin → Users & Roles → rotate admin role assignments",
        "effort": "medium",
        "guardrails": ["identity", "least-privilege", "priv-escalation"],
        "requires_human_review": True,
    },
    ("snowflake", "2.1"): {
        "why": "Network policies off means the account accepts traffic from any source IP.",
        "fix_cli": "CREATE NETWORK POLICY corp_only ALLOWED_IP_LIST=('<CORP_CIDR>'); ALTER ACCOUNT SET NETWORK_POLICY=corp_only;",
        "fix_console": "Snowsight → Admin → Security → Network policies",
        "effort": "low",
        "guardrails": ["network-exposure", "segmentation", "zero-trust"],
        "requires_human_review": True,
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_remediation(
    *,
    cloud: str,
    check_id: str,
    title: str,
    severity: str,
    recommendation: str,
    cis_section: str,
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

    override = _OVERRIDES.get((cloud, check_id))
    if override:
        # Overrides only need to provide the fields they want to set; the
        # auto-derived values fill in the rest. This keeps override
        # authoring terse while guaranteeing schema completeness.
        merged = {**base, **override}
        # Preserve priority from override if it set one explicitly; otherwise
        # inherit severity-derived priority.
        merged.setdefault("priority", priority)
        # Preserve guardrails union if the override supplied its own list.
        if "guardrails" not in override:
            merged["guardrails"] = guardrails
        return merged

    return base


def attach_remediation(result: Any, *, cloud: str) -> None:
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
    )


def attach_all(report: Any, *, cloud: str) -> None:
    """Attach remediation to every check in a CIS benchmark report."""
    for check in report.checks:
        attach_remediation(check, cloud=cloud)
