"""Posture findings over the composed demo estate, correlated end to end.

:mod:`agent_bom.demo_estate.enterprise_composition` serves an estate with
thousands of assets and evidence. It has no findings, so the claim the product
actually makes — *a finding resolves to an asset, that asset carries an identity
and a configuration, the finding sits on a correlated attack path, and it
evidences a compliance control* — was demonstrated only for the hand-authored
incident. At estate scale it was asserted, not shown.

This module closes that for the CSPM lane, and hands the rest to
:mod:`agent_bom.demo_estate.enterprise_risk`: vulnerability, secret, IaC and
runtime findings, appended here so every lane joins the same assets, the same
correlations and the same identity edges. An estate whose every finding is a CIS
check grows its risk with control coverage rather than with the estate.

Four decisions carry the weight:

**One id scheme.** A finding's asset identifier *is* the estate's ``asset_id``.
There is no demo-only resource id, no parallel spelling to reconcile later, so
``Asset.canonical_id`` is a pure function of the inventory row and every finding
on one asset joins to one node. #4637 fixed exactly this defect for live cloud
scans; re-introducing it here would demo the bug.

**One control catalog.** Checks are the ones the shipped benchmark scanners
implement — same ids, same titles, same severities — so the demo shows the
product's real control vocabulary rather than plausible-looking invented
numbering. ``tests/test_demo_estate_findings.py`` asserts every entry still
exists in ``agent_bom.cloud.*_cis_benchmark``, so a renumbered control fails
here rather than drifting silently.

**One converter.** Findings are produced by
:func:`agent_bom.finding.cloud_cis_check_to_finding`, the same function a live
cloud scan uses. Compliance classification, remediation, and scope parsing are
therefore whatever production does — not a demo-only approximation that can be
right on screen and wrong in an export.

**Unevaluable is a state, not a gap.** A deterministic slice of checks come back
``ERROR`` with no severity. They become ``CIS_ERROR`` findings in the ``unrated``
bucket: visible, counted, and never quietly rounded down to zero (#4631).

Everything is deterministic and derived from the estate's own structure, so the
same estate always yields the same findings, hashes, and screenshots.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from agent_bom.demo_estate.enterprise import (
    NARRATIVE_INCIDENT_TRACE_ID,
    EnterpriseEstate,
    EstateAsset,
)
from agent_bom.demo_estate.enterprise_correlation import (
    EnterpriseCorrelation,
    EnterpriseCorrelationResult,
    build_estate_correlations,
)
from agent_bom.demo_estate.enterprise_risk import build_risk_findings
from agent_bom.finding import Finding, cloud_cis_check_to_finding
from agent_bom.graph.severity import SEVERITY_DISPLAY_BUCKETS, severity_display_bucket

ESTATE_FINDINGS_VERSION = "enterprise_findings.v1"

# The severity vocabulary the demo summary publishes. Shared with the overview
# tiles and ``/v1/posture/counts`` via ``graph.severity`` so a tile can never
# contradict the list beside it.
ESTATE_FINDING_SEVERITY_BUCKETS: tuple[str, ...] = SEVERITY_DISPLAY_BUCKETS

# Inventory resource types that ARE an identity. A posture finding names one of
# these as the principal that can act on the affected resource, which is what
# turns "a bucket is misconfigured" into "this role can read this bucket".
IDENTITY_RESOURCE_TYPES: frozenset[str] = frozenset({"iam_role", "service_principal", "service_account", "role"})

# Share of emitted findings whose control could not be evaluated. Small but
# never zero: a demo where every control resolves cannot show that an
# unevaluable control is reported rather than dropped.
_UNEVALUABLE_SHARE = 7

# Explicit fictional triage policy.  These are security-work queues, not the
# accountable owner on ``EstateAsset``; copying the latter into Finding.owner
# would conflate service ownership with the person/team assigned remediation.
_TRIAGE_OWNER_BY_DOMAIN: dict[str, str] = {
    "cspm": "cloud-security@example.invalid",
    "vuln": "vulnerability-management@example.invalid",
    "aspm": "application-security@example.invalid",
    "dspm": "data-security@example.invalid",
    "aispm": "ai-security@example.invalid",
}


@dataclass(frozen=True, slots=True)
class EstateCheck:
    """One posture control, scoped to the resource types it can fail on.

    ``check_id``, ``title``, ``severity`` and ``recommendation`` are copied from
    the shipped benchmark scanner for this cloud — the demo must not invent
    control identity. ``setting``/``observed``/``expected`` are the
    configuration edge: what was read, and what it should have been.
    """

    provider: str
    check_id: str
    title: str
    severity: str
    cis_section: str
    recommendation: str
    resource_types: tuple[str, ...]
    setting: str
    observed: str
    expected: str
    # Percent of matching assets that fail this control. Chosen per control so
    # the estate reads like an estate: a few systemic failures, most controls
    # failing on a minority of resources, no band dominating.
    prevalence: int


_AWS_IAM = "1 - Identity and Access Management"
_AWS_STORAGE = "2 - Storage"
_AWS_NETWORK = "5 - Networking"
_AZ_STORAGE = "3 - Storage Accounts"
_AZ_DATABASE = "4 - Database Services"
_AZ_VM = "7 - Virtual Machines"
_AZ_KEYVAULT = "8 - Key Vault"
_AZ_APPSERVICE = "9 - App Service"
_GCP_IAM = "1 - Identity and Access Management"
_GCP_COMPUTE = "4 - Virtual Machines"
_GCP_STORAGE = "5 - Cloud Storage"
_GCP_SQL = "6 - Cloud SQL"
_SF_AUTH = "1 - Account and Authentication"
_SF_DATA = "3 - Data Protection"
_SF_ACCESS = "5 - Access Control"


_CATALOG: tuple[EstateCheck, ...] = (
    # ── AWS ──────────────────────────────────────────────────────────────
    EstateCheck(
        provider="aws",
        check_id="1.16",
        title="No full-admin IAM policies attached",
        severity="critical",
        cis_section=_AWS_IAM,
        recommendation="Remove or scope down policies that grant '*' on '*' resources.",
        resource_types=("iam_role",),
        setting="attached_policy_actions",
        observed="Action '*' on Resource '*'",
        expected="Least-privilege actions scoped to named resources",
        prevalence=9,
    ),
    EstateCheck(
        provider="aws",
        check_id="1.15",
        title="IAM permissions granted via groups or roles only",
        severity="medium",
        cis_section=_AWS_IAM,
        recommendation="Remove inline and directly attached policies from IAM users; use groups instead.",
        resource_types=("iam_role",),
        setting="inline_policy_count",
        observed="2 inline policies attached directly",
        expected="0 inline policies; permissions granted through groups or roles",
        prevalence=21,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.1.2",
        title="S3 bucket server-side encryption enabled",
        severity="medium",
        cis_section=_AWS_STORAGE,
        recommendation="Enable default encryption (SSE-S3 or SSE-KMS) on all S3 buckets.",
        resource_types=("bucket",),
        setting="ServerSideEncryptionConfiguration",
        observed="absent",
        expected="ApplyServerSideEncryptionByDefault=aws:kms",
        prevalence=24,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.1.1",
        title="S3 account-level public access block configured",
        severity="high",
        cis_section=_AWS_STORAGE,
        recommendation="Enable all four S3 public access block settings at the account level.",
        resource_types=("bucket",),
        setting="PublicAccessBlockConfiguration.BlockPublicPolicy",
        observed="false",
        expected="true",
        prevalence=11,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.1.4",
        title="S3 bucket versioning enabled",
        severity="medium",
        cis_section=_AWS_STORAGE,
        recommendation="Enable versioning on all S3 buckets for data protection.",
        resource_types=("bucket",),
        setting="VersioningConfiguration.Status",
        observed="Suspended",
        expected="Enabled",
        prevalence=18,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.3.1",
        title="RDS encryption at rest enabled",
        severity="high",
        cis_section=_AWS_STORAGE,
        recommendation="Enable encryption at rest when creating RDS instances (cannot be changed post-creation).",
        resource_types=("database",),
        setting="StorageEncrypted",
        observed="false",
        expected="true",
        prevalence=14,
    ),
    EstateCheck(
        provider="aws",
        check_id="2.3.2",
        title="RDS auto minor version upgrade enabled",
        severity="medium",
        cis_section=_AWS_STORAGE,
        recommendation="Enable auto minor version upgrade on all RDS instances.",
        resource_types=("database",),
        setting="AutoMinorVersionUpgrade",
        observed="false",
        expected="true",
        prevalence=27,
    ),
    EstateCheck(
        provider="aws",
        check_id="5.2",
        title="No unrestricted ingress to admin ports (22, 3389)",
        severity="high",
        cis_section=_AWS_NETWORK,
        recommendation="Restrict SSH (22) and RDP (3389) to specific IP ranges.",
        resource_types=("instance", "cluster"),
        setting="security_group_ingress",
        observed="0.0.0.0/0 -> tcp/22",
        expected="Ingress restricted to approved CIDR ranges",
        prevalence=13,
    ),
    EstateCheck(
        provider="aws",
        check_id="5.3",
        title="Default security group restricts all traffic",
        severity="medium",
        cis_section=_AWS_NETWORK,
        recommendation="Remove all inbound and outbound rules from default security groups.",
        resource_types=("instance", "function"),
        setting="default_security_group_rules",
        observed="1 inbound rule, 1 outbound rule",
        expected="0 inbound rules, 0 outbound rules",
        prevalence=16,
    ),
    # ── Azure ────────────────────────────────────────────────────────────
    EstateCheck(
        provider="azure",
        check_id="3.1",
        title="Secure transfer required on storage accounts",
        severity="high",
        cis_section=_AZ_STORAGE,
        recommendation="Enable 'Secure transfer required' on all storage accounts to enforce HTTPS-only access.",
        resource_types=("storage_account",),
        setting="supportsHttpsTrafficOnly",
        observed="false",
        expected="true",
        prevalence=12,
    ),
    EstateCheck(
        provider="azure",
        check_id="3.7",
        title="Blob containers set to private access",
        severity="high",
        cis_section=_AZ_STORAGE,
        recommendation="Disable public blob access at the storage account level and audit all containers.",
        resource_types=("storage_account",),
        setting="allowBlobPublicAccess",
        observed="true",
        expected="false",
        prevalence=9,
    ),
    EstateCheck(
        provider="azure",
        check_id="3.11",
        title="Private endpoints used for storage accounts",
        severity="high",
        cis_section=_AZ_STORAGE,
        recommendation="Configure private endpoints for all storage accounts to restrict network access.",
        resource_types=("storage_account",),
        setting="privateEndpointConnections",
        observed="0 connections; publicNetworkAccess=Enabled",
        expected="At least one approved private endpoint; public network access disabled",
        prevalence=26,
    ),
    EstateCheck(
        provider="azure",
        check_id="4.1.2",
        title="Transparent Data Encryption enabled on SQL servers",
        severity="high",
        cis_section=_AZ_DATABASE,
        recommendation="Enable Transparent Data Encryption on all SQL databases.",
        resource_types=("sql_database",),
        setting="transparentDataEncryption.state",
        observed="Disabled",
        expected="Enabled",
        prevalence=15,
    ),
    EstateCheck(
        provider="azure",
        check_id="4.2.1",
        title="TLS 1.2 or higher on database servers",
        severity="high",
        cis_section=_AZ_DATABASE,
        recommendation="Set the minimum TLS version to TLS 1.2 on all Azure SQL, MySQL, and PostgreSQL servers.",
        resource_types=("sql_database",),
        setting="minimalTlsVersion",
        observed="1.0",
        expected="1.2",
        prevalence=19,
    ),
    EstateCheck(
        provider="azure",
        check_id="7.1",
        title="Virtual machines use Managed Disks",
        severity="medium",
        cis_section=_AZ_VM,
        recommendation="Migrate all VM disks to Managed Disks for improved reliability and security.",
        resource_types=("virtual_machine",),
        setting="storageProfile.osDisk.managedDisk",
        observed="absent (unmanaged VHD in a storage account)",
        expected="Managed disk reference",
        prevalence=17,
    ),
    EstateCheck(
        provider="azure",
        check_id="8.1",
        title="Expiration date set on Key Vault keys",
        severity="medium",
        cis_section=_AZ_KEYVAULT,
        recommendation="Set an expiration date on all Key Vault keys to enforce key rotation.",
        resource_types=("key_vault",),
        setting="key.attributes.exp",
        observed="null",
        expected="A rotation date within policy",
        prevalence=100,
    ),
    EstateCheck(
        provider="azure",
        check_id="8.6",
        title="Key Vault secrets have a content type set",
        severity="low",
        cis_section=_AZ_KEYVAULT,
        recommendation="Set a content type on all Key Vault secrets so consumers can validate what they retrieve.",
        resource_types=("key_vault",),
        setting="secret.contentType",
        observed="null on 3 of 5 secrets",
        expected="A content type on every secret",
        prevalence=100,
    ),
    EstateCheck(
        provider="azure",
        check_id="9.1",
        title="App Service Authentication configured",
        severity="high",
        cis_section=_AZ_APPSERVICE,
        recommendation="Enable App Service Authentication (EasyAuth) on all web apps.",
        resource_types=("function_app",),
        setting="siteAuthSettings.enabled",
        observed="false",
        expected="true",
        prevalence=22,
    ),
    # ── GCP ──────────────────────────────────────────────────────────────
    EstateCheck(
        provider="gcp",
        check_id="1.4",
        title="No user-managed service account keys",
        severity="medium",
        cis_section=_GCP_IAM,
        recommendation="Delete user-managed service account keys and use short-lived credentials via Workload Identity.",
        resource_types=("service_account",),
        setting="user_managed_keys",
        observed="1 user-managed key, created 412 days ago",
        expected="0 user-managed keys; short-lived credentials only",
        prevalence=23,
    ),
    EstateCheck(
        provider="gcp",
        check_id="3.6",
        title="SSH (port 22) restricted from the internet",
        severity="critical",
        cis_section="3 - Networking",
        recommendation="Remove or restrict firewall rules that allow TCP port 22 from 0.0.0.0/0 or ::/0.",
        resource_types=("instance",),
        setting="firewall_rule.sourceRanges",
        observed="0.0.0.0/0 -> tcp/22",
        expected="Approved CIDR ranges only",
        prevalence=7,
    ),
    EstateCheck(
        provider="gcp",
        check_id="4.1",
        title="Instances not using default service account",
        severity="high",
        cis_section=_GCP_COMPUTE,
        recommendation="Create and assign a custom service account to each VM instance instead of using the default.",
        resource_types=("instance",),
        setting="serviceAccounts[0].email",
        observed="compute default service account",
        expected="A dedicated least-privilege service account",
        prevalence=20,
    ),
    EstateCheck(
        provider="gcp",
        check_id="5.1",
        title="Cloud Storage buckets not publicly accessible",
        severity="high",
        cis_section=_GCP_STORAGE,
        recommendation="Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
        resource_types=("bucket",),
        setting="iamPolicy.bindings",
        observed="allUsers has roles/storage.objectViewer",
        expected="No allUsers or allAuthenticatedUsers principals",
        prevalence=8,
    ),
    EstateCheck(
        provider="gcp",
        check_id="5.2",
        title="Uniform bucket-level access enabled on buckets",
        severity="medium",
        cis_section=_GCP_STORAGE,
        recommendation="Enable uniform bucket-level access on all Cloud Storage buckets to use IAM exclusively.",
        resource_types=("bucket",),
        setting="iamConfiguration.uniformBucketLevelAccess.enabled",
        observed="false",
        expected="true",
        prevalence=29,
    ),
    EstateCheck(
        provider="gcp",
        check_id="6.2",
        title="Cloud SQL instances lack public IPs",
        severity="high",
        cis_section=_GCP_SQL,
        recommendation="Remove public IP addresses from Cloud SQL instances and use private IP or Cloud SQL Proxy.",
        resource_types=("database",),
        setting="settings.ipConfiguration.ipv4Enabled",
        observed="true",
        expected="false",
        prevalence=16,
    ),
    # ── Snowflake ────────────────────────────────────────────────────────
    EstateCheck(
        provider="snowflake",
        check_id="1.4",
        title="ACCOUNTADMIN granted to at most 2 users",
        severity="critical",
        cis_section=_SF_AUTH,
        recommendation="Limit ACCOUNTADMIN grants to a maximum of 2 users.",
        resource_types=("role",),
        setting="accountadmin_grantees",
        observed="6 users hold ACCOUNTADMIN",
        expected="At most 2 users",
        prevalence=10,
    ),
    EstateCheck(
        provider="snowflake",
        check_id="5.1",
        title="PUBLIC role has no direct privilege grants",
        severity="high",
        cis_section=_SF_ACCESS,
        recommendation="Revoke all grants from the PUBLIC role: REVOKE ALL ON <object> FROM ROLE PUBLIC;",
        resource_types=("role", "warehouse"),
        setting="grants_to_public_role",
        observed="SELECT granted to PUBLIC",
        expected="No privileges granted to PUBLIC",
        prevalence=18,
    ),
    EstateCheck(
        provider="snowflake",
        check_id="3.1",
        title="Tri-Secret Secure (customer-managed key) enabled",
        severity="high",
        cis_section=_SF_DATA,
        recommendation="Contact Snowflake support to enable Tri-Secret Secure with your cloud KMS.",
        resource_types=("database", "table"),
        setting="tri_secret_secure",
        observed="disabled",
        expected="enabled with a customer-managed key",
        prevalence=12,
    ),
    EstateCheck(
        provider="snowflake",
        check_id="3.2",
        title="Data sharing restricted to authorized accounts",
        severity="medium",
        cis_section=_SF_DATA,
        recommendation="Review outbound shares and remove unauthorized consumers.",
        resource_types=("share", "stage"),
        setting="share_consumers",
        observed="1 consumer outside the approved account list",
        expected="Only approved consumer accounts",
        prevalence=25,
    ),
)


def _catalog_index() -> dict[tuple[str, str], tuple[EstateCheck, ...]]:
    index: dict[tuple[str, str], list[EstateCheck]] = {}
    for check in _CATALOG:
        for resource_type in check.resource_types:
            index.setdefault((check.provider, resource_type), []).append(check)
    return {key: tuple(value) for key, value in index.items()}


_CATALOG_BY_TARGET = _catalog_index()


class EstateFindingSummary(BaseModel):
    """Unbounded totals for the estate's posture, whatever a view chooses to show.

    Every field here counts the WHOLE estate. A bounded list beside this summary
    is a page of it, never a redefinition of it — which is why the story can cap
    what it renders without any surface reporting a page size as a total.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = ESTATE_FINDINGS_VERSION
    total: int = Field(ge=0)
    by_severity: dict[str, int]
    assets_affected: int = Field(ge=0)
    assets_total: int = Field(ge=0)
    controls_evidenced: int = Field(ge=0)
    frameworks_evidenced: tuple[str, ...] = ()
    attack_paths_evidenced: int = Field(ge=0)
    identities_implicated: int = Field(ge=0)


class EstateFindingView(BaseModel):
    """One finding rendered as the chain it belongs to, not as a row of text.

    Deliberately narrow: enough to prove finding -> asset -> identity ->
    configuration -> attack path -> control on screen, without shipping the full
    finding payload for every row at estate scale.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    finding_type: str
    severity: str
    severity_bucket: str
    title: str
    security_domain: str
    provider: str
    account_ref: str
    region: str = ""
    environment: str = ""
    asset_id: str
    asset_canonical_id: str
    asset_display_name: str
    identity_asset_id: str = ""
    identity_display_name: str = ""
    identity_actor_id: str = ""
    configuration_setting: str
    configuration_observed: str
    configuration_expected: str
    controls: tuple[str, ...]
    correlation_id: str = ""
    attack_path: tuple[str, ...] = ()


def _stable_index(*parts: str) -> int:
    """Deterministic pseudo-index derived from the identity of the thing itself.

    Same derivation as :mod:`agent_bom.demo_estate.enterprise_scale`: generation
    depends only on structure, so an estate yields the same posture on every
    machine and every run and a demo can be screenshotted.
    """
    return int.from_bytes(hashlib.sha256("|".join(parts).encode("utf-8")).digest()[:4], "big")


def _identities_by_account(estate: EnterpriseEstate) -> dict[tuple[str, str], tuple[EstateAsset, ...]]:
    """Index the inventory's identities by the account boundary they live in.

    Scoped to ``(provider, account_scope)`` on purpose. A posture finding must
    name a principal that can actually reach the affected resource; borrowing an
    identity from a neighbouring account would draw an edge that does not exist
    and would be exactly the kind of over-claim the graph must never make.
    """
    grouped: dict[tuple[str, str], list[EstateAsset]] = {}
    for asset in estate.assets:
        if asset.resource_type in IDENTITY_RESOURCE_TYPES:
            grouped.setdefault((asset.provider, asset.account_scope), []).append(asset)
    return {key: tuple(sorted(value, key=lambda a: a.asset_id)) for key, value in grouped.items()}


def _actors_by_asset(estate: EnterpriseEstate) -> dict[str, tuple[str, ...]]:
    """Index the principals the estate's own evidence observed acting on each asset.

    The second, independent half of the identity edge. An account can legitimately
    inventory no identity of its own — an Entra tenant holds the service
    principals while the subscription holds the vault — and requiring an
    inventoried identity in that case silently dropped every finding in the
    account, including the PHI table at the end of the incident chain. An
    observed actor is evidence, not inference, so it stands on its own.
    """
    grouped: dict[str, set[str]] = {}
    for event in estate.observations:
        for resource_id in event.resource_ids:
            grouped.setdefault(resource_id, set()).add(event.actor_id)
    return {key: tuple(sorted(value)) for key, value in grouped.items()}


def _pick_identity(candidates: tuple[EstateAsset, ...], *, subject: EstateAsset, seed: int) -> EstateAsset:
    """Choose the principal this finding implicates, preferring one that is not the subject.

    A misconfigured role legitimately implicates itself, but a row reading
    ``role X is exposed to role X`` reads as a placeholder even when it is
    accurate. Prefer another principal in the same account when one exists, and
    fall back to the subject only when it is the account's sole identity.
    """
    others = tuple(asset for asset in candidates if asset.asset_id != subject.asset_id)
    pool = others or candidates
    return pool[seed % len(pool)]


def _paths_by_asset(correlations: tuple[EnterpriseCorrelation, ...]) -> dict[str, EnterpriseCorrelation]:
    """Map each asset to the multi-asset correlation it participates in.

    Single-asset traces are excluded: a "path" through one node is not a path,
    and labelling it one would inflate the attack-path count with noise.
    """

    # Ranked, not first-wins. ``setdefault`` over an iteration order made the
    # choice a function of trace-id sort order, so any change to how trace ids
    # are derived silently reassigned assets to different correlations — and
    # since a correlation's kind decides whether an asset reports every control,
    # that changed the estate's finding count. Rank explicitly: the richest
    # chain wins, ties broken by id.
    def rank(correlation: EnterpriseCorrelation) -> tuple[int, int, int, str]:
        # The hand-authored incident always claims its own assets. It is the
        # thing the demo is for, and a generated journey that happens to span
        # the same number of sources must not take its place on the surfaces
        # that lead with "the incident".
        return (
            0 if correlation.trace_id == NARRATIVE_INCIDENT_TRACE_ID else 1,
            -len(set(correlation.sources)),
            -len(correlation.asset_path),
            correlation.correlation_id,
        )

    by_asset: dict[str, EnterpriseCorrelation] = {}
    for correlation in sorted(correlations, key=rank):
        if len(correlation.asset_path) < 2:
            continue
        for asset_id in correlation.asset_path:
            by_asset.setdefault(asset_id, correlation)
    return by_asset


# Correlation kinds whose assets report every applicable control rather than a
# prevalence sample. Deliberately narrow.
#
# The rule used to be "any asset on any correlated path", which was safe while
# four correlations existed. Now that the estate produces thousands of traces,
# that rule reached most of the inventory and quadrupled the posture lane — the
# estate's risk would once again have been a function of control coverage, just
# arrived at from the other direction. An asset on an egress attempt or a
# remediation is genuinely worth reporting in full; an asset seen in an identity
# session is not.
_FULL_CONTROL_KINDS: frozenset[str] = frozenset({"data_egress_attempt", "remediation"})


def _build_check_payload(asset: EstateAsset, check: EstateCheck, *, unevaluable: bool) -> dict[str, object]:
    """Shape one posture result exactly as a live benchmark scanner emits it."""
    evidence = (
        f"{check.setting} could not be read on {asset.display_name}; the control was not evaluated."
        if unevaluable
        else f"{check.setting} on {asset.display_name} is {check.observed}; expected {check.expected}."
    )
    payload: dict[str, object] = {
        "check_id": check.check_id,
        "title": check.title,
        # An unevaluable control has no severity to report. Passing "" rather
        # than guessing "medium" is what puts it in the ``unrated`` bucket
        # instead of inventing a rating the evidence does not support.
        "severity": "" if unevaluable else check.severity,
        "status": "ERROR" if unevaluable else "FAIL",
        "cis_section": check.cis_section,
        "evidence": evidence,
        "recommendation": check.recommendation,
        "resource_ids": [asset.asset_id],
        "account_id": asset.account_scope,
        "region": asset.region,
        "environment": asset.environment,
        "attack_techniques": [] if unevaluable else list(_attack_techniques(check)),
    }
    return payload


_SECTION_TACTIC_CACHE: dict[tuple[str, str], tuple[str, ...]] = {}


def _attack_techniques(check: EstateCheck) -> tuple[str, ...]:
    """Resolve ATT&CK techniques with the product's own CIS tagger.

    ``mitre_attack.tag_cis_check`` reads the live technique catalog rather than a
    frozen list, so the demo's ATT&CK coverage is whatever the shipped tagger
    produces for that control — a hand-written technique list here would drift
    away from the product the moment the catalog moved.
    """
    key = (check.provider, check.check_id)
    cached = _SECTION_TACTIC_CACHE.get(key)
    if cached is not None:
        return cached

    from agent_bom.cloud.aws_cis_benchmark import CheckStatus
    from agent_bom.mitre_attack import tag_cis_check

    class _CheckShim:
        status = CheckStatus.FAIL
        cis_section = check.cis_section
        title = check.title

    techniques = tuple(tag_cis_check(_CheckShim()))
    _SECTION_TACTIC_CACHE[key] = techniques
    return techniques


def build_estate_findings(
    estate: EnterpriseEstate,
    *,
    correlation_result: EnterpriseCorrelationResult | None = None,
) -> tuple[Finding, ...]:
    """Return the estate's deterministic posture findings, chain intact.

    ``correlation_result`` is accepted so a caller that already correlated the
    estate (the demo story does) does not pay for it twice. Omitted, the
    payload-free correlation is used: findings need the paths, not the
    normalized event bodies.
    """
    correlations = correlation_result.correlations if correlation_result is not None else build_estate_correlations(estate)
    path_by_asset = _paths_by_asset(correlations)
    identities = _identities_by_account(estate)
    actors = _actors_by_asset(estate)

    findings: list[Finding] = []
    for asset in estate.assets:
        checks = _CATALOG_BY_TARGET.get((asset.provider, asset.resource_type))
        if not checks:
            continue
        account_identities = identities.get((asset.provider, asset.account_scope), ())
        asset_actors = actors.get(asset.asset_id, ())
        if not account_identities and not asset_actors:
            # Neither an inventoried principal in this account nor an observed
            # one on this asset: there is no identity edge to draw, and a
            # finding with a dangling half-chain is the thing this module exists
            # to avoid.
            continue
        correlation = path_by_asset.get(asset.asset_id)
        for check in checks:
            seed = _stable_index(asset.asset_id, check.provider, check.check_id)
            # Assets on the *incident* path always report their applicable
            # controls. The incident is the thing the demo is for; leaving its
            # own assets to a probability roll is how a demo loses its story.
            # Everything else stays on prevalence — see ``_FULL_CONTROL_KINDS``.
            full_report = correlation is not None and correlation.kind in _FULL_CONTROL_KINDS
            if not full_report and seed % 100 >= check.prevalence:
                continue
            identity = _pick_identity(account_identities, subject=asset, seed=seed) if account_identities else None
            actor = asset_actors[seed % len(asset_actors)] if asset_actors else ""
            unevaluable = (seed // 100) % 100 < _UNEVALUABLE_SHARE
            finding = cloud_cis_check_to_finding(
                _build_check_payload(asset, check, unevaluable=unevaluable),
                asset.provider,
            )
            # Two vocabularies, deliberately. The keys on the left are the ones
            # ``evidence.policy`` classifies as tier A, so they survive
            # ``redact_for_persistence`` and the chain stays joinable on the
            # persisted findings list, the exports and the API. The richer keys
            # below them are for the demo story, which is computed live from
            # this same object and never persisted. Nothing here asks the
            # redactor to relax: a default-deny evidence policy is worth more
            # than a demo field, so the demo speaks the policy's language.
            finding.evidence.update(
                {
                    "resource_id": asset.asset_id,
                    "resource_name": asset.display_name,
                    "resource_type": asset.resource_type,
                    "control_id": f"CIS-{check.check_id}",
                    "tenant_id": estate.tenant_id,
                    "synthetic": True,
                    "fictional": True,
                    "disclosure": estate.disclosure,
                    "estate_id": estate.estate_id,
                    "data_classifications": list(asset.data_classifications),
                    "configuration": {
                        "setting": check.setting,
                        "observed": "unreadable" if unevaluable else check.observed,
                        "expected": check.expected,
                    },
                }
            )
            if identity is not None:
                finding.evidence["principal_id"] = identity.asset_id
                finding.evidence["identity_asset_id"] = identity.asset_id
                finding.evidence["identity_display_name"] = identity.display_name
                finding.evidence["identity_resource_type"] = identity.resource_type
            if actor:
                finding.evidence["actor_id"] = actor
                finding.evidence["identity_actor_id"] = actor
            if correlation is not None:
                finding.evidence["correlation_id"] = correlation.correlation_id
                finding.evidence["correlation_kind"] = correlation.kind
                finding.evidence["attack_path"] = list(correlation.asset_path)
            findings.append(finding)

    # The other four scanners. Posture alone made the estate's risk a function of
    # control coverage rather than of the estate — every one of 439 findings was
    # a CIS check, so an AI service, a leaked credential and a vulnerable image
    # all read as "no findings". They correlate onto the same paths through the
    # same asset ids, so they are appended here rather than served separately.
    assets_by_id = {asset.asset_id: asset for asset in estate.assets}
    kept_risk_findings: list[Finding] = []
    for finding in build_risk_findings(estate):
        asset_id = finding.asset.identifier or ""
        subject = assets_by_id.get(asset_id)
        correlation = path_by_asset.get(asset_id)
        if correlation is not None:
            finding.evidence["correlation_id"] = correlation.correlation_id
            finding.evidence["correlation_kind"] = correlation.kind
            finding.evidence["attack_path"] = list(correlation.asset_path)
        actor_pool = actors.get(asset_id, ())
        if actor_pool:
            actor = actor_pool[_stable_index(finding.id) % len(actor_pool)]
            finding.evidence["actor_id"] = actor
            finding.evidence["identity_actor_id"] = actor
        # Every finding names a principal, in the same two vocabularies the
        # posture lane uses. A vulnerability with no identity edge is a row of
        # text: what makes it actionable is *which principal the vulnerable
        # process holds*. The inventory already declares that on the asset, so
        # this reads it rather than inferring one.
        if subject is not None:
            principal = assets_by_id.get(subject.tags.get("uses_identity", ""))
            if principal is None:
                pool = identities.get((subject.provider, subject.account_scope), ())
                if pool:
                    principal = _pick_identity(pool, subject=subject, seed=_stable_index(finding.id))
            if principal is not None:
                finding.evidence["principal_id"] = principal.asset_id
                finding.evidence["identity_asset_id"] = principal.asset_id
                finding.evidence["identity_display_name"] = principal.display_name
                finding.evidence["identity_resource_type"] = principal.resource_type
        # Same rule the posture lane above applies, for the same reason: neither
        # an inventoried principal nor an observed actor means there is no
        # identity edge to draw, and a finding with a dangling half-chain is
        # what this module exists to avoid.
        if finding.evidence.get("identity_asset_id") or finding.evidence.get("identity_actor_id"):
            kept_risk_findings.append(finding)
    findings.extend(kept_risk_findings)
    current_snapshot = next(snapshot for snapshot in estate.snapshots if snapshot.stage.value == "current")
    first_seen = current_snapshot.observed_at.isoformat()
    for finding in findings:
        finding.owner = _TRIAGE_OWNER_BY_DOMAIN[finding.security_domain]
        finding.first_seen = first_seen
        finding.evidence["triage_owner_source"] = "synthetic-demo-domain-routing"
    return tuple(findings)


def summarize_estate_findings(estate: EnterpriseEstate, findings: tuple[Finding, ...]) -> EstateFindingSummary:
    """Return whole-estate totals for ``findings``.

    Counted from the findings themselves rather than from any generation-time
    bookkeeping, so a summary can never describe a set the caller does not hold.
    """
    by_severity = dict.fromkeys(ESTATE_FINDING_SEVERITY_BUCKETS, 0)
    controls: set[tuple[str, str]] = set()
    frameworks: set[str] = set()
    assets: set[str] = set()
    identities: set[str] = set()
    paths: set[str] = set()
    for finding in findings:
        by_severity[severity_display_bucket(finding.severity)] += 1
        assets.add(finding.asset.identifier or "")
        for key in ("identity_asset_id", "identity_actor_id"):
            identity_id = finding.evidence.get(key)
            if identity_id:
                identities.add(str(identity_id))
        correlation_id = finding.evidence.get("correlation_id")
        if correlation_id:
            paths.add(str(correlation_id))
        for tag in finding.normalized_controls():
            controls.add((tag.framework, tag.control))
            frameworks.add(tag.framework)
    return EstateFindingSummary(
        total=len(findings),
        by_severity=by_severity,
        assets_affected=len(assets),
        assets_total=len(estate.assets),
        controls_evidenced=len(controls),
        frameworks_evidenced=tuple(sorted(frameworks)),
        attack_paths_evidenced=len(paths),
        identities_implicated=len(identities),
    )


def to_finding_view(finding: Finding) -> EstateFindingView:
    """Project one finding into the compact chain row the demo surfaces render."""
    configuration = finding.evidence.get("configuration") or {}
    return EstateFindingView(
        finding_id=finding.id,
        finding_type=finding.finding_type.value,
        severity=finding.severity,
        severity_bucket=severity_display_bucket(finding.severity),
        title=finding.title,
        security_domain=finding.security_domain,
        provider=finding.provider or "",
        account_ref=finding.account_ref or "",
        region=finding.region or "",
        environment=finding.environment or "",
        asset_id=finding.asset.identifier or "",
        asset_canonical_id=finding.asset.canonical_id,
        asset_display_name=str(finding.evidence.get("resource_name") or ""),
        identity_asset_id=str(finding.evidence.get("identity_asset_id") or ""),
        identity_display_name=str(finding.evidence.get("identity_display_name") or ""),
        identity_actor_id=str(finding.evidence.get("identity_actor_id") or ""),
        configuration_setting=str(configuration.get("setting") or ""),
        configuration_observed=str(configuration.get("observed") or ""),
        configuration_expected=str(configuration.get("expected") or ""),
        controls=tuple(f"{tag.framework}:{tag.control}" for tag in finding.normalized_controls()),
        correlation_id=str(finding.evidence.get("correlation_id") or ""),
        attack_path=tuple(finding.evidence.get("attack_path") or ()),
    )


__all__ = [
    "ESTATE_FINDINGS_VERSION",
    "ESTATE_FINDING_SEVERITY_BUCKETS",
    "IDENTITY_RESOURCE_TYPES",
    "EstateCheck",
    "EstateFindingSummary",
    "EstateFindingView",
    "build_estate_findings",
    "summarize_estate_findings",
    "to_finding_view",
]
