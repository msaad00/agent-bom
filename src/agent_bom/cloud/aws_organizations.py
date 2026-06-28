"""AWS Organizations inventory — org → OUs → accounts → SCPs (read-only, agentless).

Answers "what does our AWS org / multi-account estate look like" for a CISO or an
agent: the organization hierarchy (organizational units), every member account
(scales to thousands via pagination), and the Service Control Policies that bound
them. Emitted as ORG / ACCOUNT / POLICY graph nodes with ``CONTAINS`` hierarchy so
the estate is traversable top-down then drill-down — the AWS analogue of the Azure
management-group hierarchy.

Trust posture: read-only (``organizations:Describe*`` / ``List*`` only — all in the
SecurityAudit / ViewOnlyAccess managed policies), agentless, no writes. A standalone
account (not in an org) degrades to ``status: "not_in_org"``; missing creds / SDK
degrade to a clear status, never a crash.
"""

from __future__ import annotations

import os
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from .normalization import sanitize_discovery_warning

INVENTORY_ENV_FLAG = "AGENT_BOM_CLOUD_INVENTORY"
_TRUTHY = {"1", "true", "yes", "on"}

_AWS_ORG_PERMISSIONS: tuple[str, ...] = (
    "organizations:DescribeOrganization",
    "organizations:ListRoots",
    "organizations:ListOrganizationalUnitsForParent",
    "organizations:ListAccounts",
    "organizations:ListPolicies",
    "organizations:ListTargetsForPolicy",
)

# Cap the OU recursion + account pagination defensively for very large orgs.
_MAX_OU_DEPTH = 8

# ---------------------------------------------------------------------------
# Cross-account scan fan-out (opt-in, read-only)
#
# The AWS counterpart of the Azure all-subscriptions and GCP all-projects
# fan-out: from the management / delegated-admin account, assume a read-only
# role in every member account and run the per-account inventory + CIS benchmark
# against the assumed, short-lived session. Default OFF and gated separately
# from single-account inventory so existing automation is unchanged.
# ---------------------------------------------------------------------------

# Opt-in org fan-out gate. Default OFF; symmetric with the other providers'
# tenant/estate-wide fan-out gates (AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS /
# AGENT_BOM_GCP_ALL_PROJECTS) and the Snowflake org roll-up (AGENT_BOM_SNOWFLAKE_ORG).
ORG_FANOUT_ENV_FLAG = "AGENT_BOM_AWS_ORG_INVENTORY"

# Read-only role assumed in each member account. The conventional
# ``OrganizationAccountAccessRole`` is full-admin and deliberately NOT the
# default — operators deploy a least-privilege, SecurityAudit/ViewOnlyAccess
# read-only role (e.g. via a CloudFormation StackSet) under this name in every
# account. Override with ``AGENT_BOM_AWS_ORG_ROLE_NAME``.
ORG_ROLE_NAME_ENV = "AGENT_BOM_AWS_ORG_ROLE_NAME"
_DEFAULT_ORG_ROLE_NAME = "agent-bom-readonly"

# Optional confused-deputy ExternalId presented to every per-account AssumeRole.
ORG_EXTERNAL_ID_ENV = "AGENT_BOM_AWS_ORG_EXTERNAL_ID"

# RoleSessionName stamped on the temporary credentials (visible in CloudTrail).
_ORG_SESSION_NAME = "agent-bom-readonly"

# Defensive cap so an org with thousands of accounts can't fan out unbounded
# without an operator opting into a larger budget. Mirrors GCP's MAX_PROJECTS
# (200) and Snowflake's MAX_ACCOUNTS.
_DEFAULT_MAX_ACCOUNTS = 200

# The single read-only action the fan-out adds on top of the org-enumeration
# permissions: assuming the per-account read-only role.
_AWS_ORG_ASSUME_PERMISSION = "sts:AssumeRole"


def discover_organization(profile: str | None = None, *, force: bool = False) -> dict[str, Any]:
    """Enumerate the AWS Organization: OUs, member accounts, and SCPs (read-only).

    Returns a payload destined for ``report_json["aws_organization"]`` carrying a
    ``status``: ``disabled`` / ``boto3_missing`` / ``no_credentials`` /
    ``not_in_org`` / ``ok``. Never raises.
    """
    result: dict[str, Any] = {
        "status": "disabled",
        "org_id": "",
        "master_account_id": "",
        "feature_set": "",
        "organizational_units": [],
        "accounts": [],
        "scps": [],
        "findings": [],
        "warnings": [],
        "discovery_envelope": None,
    }
    if not force and os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() not in _TRUTHY:
        return result

    try:
        import boto3  # noqa: F401
        from botocore.exceptions import NoCredentialsError
    except ImportError:
        result["status"] = "boto3_missing"
        result["warnings"] = ["boto3 is required for AWS org inventory. Install with: pip install 'agent-bom[aws]'"]
        return result

    warnings: list[str] = result["warnings"]
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        org = session.client("organizations")
    except Exception as exc:  # noqa: BLE001
        result["status"] = "no_credentials"
        warnings.append(sanitize_discovery_warning(exc))
        return result

    try:
        desc = org.describe_organization().get("Organization", {})
        result["org_id"] = str(desc.get("Id", "") or "")
        result["master_account_id"] = str(desc.get("MasterAccountId", "") or "")
        result["feature_set"] = str(desc.get("FeatureSet", "") or "")
    except NoCredentialsError:
        result["status"] = "no_credentials"
        warnings.append("AWS credentials not found.")
        return result
    except Exception as exc:  # noqa: BLE001
        # AWSOrganizationsNotInUseException → a standalone account, not an error.
        if "NotInUse" in type(exc).__name__ or "AWSOrganizationsNotInUse" in str(exc):
            result["status"] = "not_in_org"
        else:
            result["status"] = "ok"  # partial; record what we can
            warnings.append(f"Could not describe organization: {sanitize_discovery_warning(exc)}")
        return result

    # Roots + OU tree (recursive).
    root_ids: list[str] = []
    try:
        for root in org.list_roots().get("Roots", []):
            rid = str(root.get("Id", "") or "")
            if rid:
                root_ids.append(rid)
                result["organizational_units"].append(
                    {"id": rid, "name": str(root.get("Name", "Root") or "Root"), "parent_id": "", "is_root": True}
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list roots: {sanitize_discovery_warning(exc)}")

    def _walk_ous(parent_id: str, depth: int) -> None:
        if depth > _MAX_OU_DEPTH:
            return
        try:
            paginator = org.get_paginator("list_organizational_units_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get("OrganizationalUnits", []):
                    oid = str(ou.get("Id", "") or "")
                    if not oid:
                        continue
                    result["organizational_units"].append(
                        {"id": oid, "name": str(ou.get("Name", "") or ""), "parent_id": parent_id, "is_root": False}
                    )
                    _walk_ous(oid, depth + 1)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list OUs under {parent_id}: {sanitize_discovery_warning(exc)}")

    for rid in root_ids:
        _walk_ous(rid, 0)

    # Member accounts, placed under their OU/root (list per-parent so each account
    # carries its parent for the CONTAINS hierarchy; scales via pagination).
    seen_accounts: set[str] = set()
    for parent in result["organizational_units"]:
        parent_id = parent["id"]
        try:
            paginator = org.get_paginator("list_accounts_for_parent")
            for page in paginator.paginate(ParentId=parent_id):
                for acct in page.get("Accounts", []):
                    aid = str(acct.get("Id", "") or "")
                    if not aid or aid in seen_accounts:
                        continue
                    seen_accounts.add(aid)
                    result["accounts"].append(
                        {
                            "id": aid,
                            "name": str(acct.get("Name", "") or ""),
                            "email": str(acct.get("Email", "") or ""),
                            "status": str(acct.get("Status", "") or ""),
                            "ou_id": parent_id,
                        }
                    )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Could not list accounts under {parent_id}: {sanitize_discovery_warning(exc)}")

    # Service Control Policies + their attachment targets.
    try:
        paginator = org.get_paginator("list_policies")
        for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
            for pol in page.get("Policies", []):
                pid = str(pol.get("Id", "") or "")
                if not pid:
                    continue
                targets: list[str] = []
                try:
                    tpag = org.get_paginator("list_targets_for_policy")
                    for tpage in tpag.paginate(PolicyId=pid):
                        targets.extend(str(t.get("TargetId", "")) for t in tpage.get("Targets", []) if t.get("TargetId"))
                except Exception:  # noqa: BLE001 — targets are best-effort
                    pass
                result["scps"].append(
                    {
                        "id": pid,
                        "name": str(pol.get("Name", "") or ""),
                        "aws_managed": bool(pol.get("AwsManaged")),
                        "targets": targets,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list SCPs: {sanitize_discovery_warning(exc)}")

    # Findings.
    customer_scps = [s for s in result["scps"] if not s["aws_managed"]]
    if not customer_scps and result["accounts"]:
        result["findings"].append(
            {
                "severity": "medium",
                "title": "No custom Service Control Policies",
                "detail": f"{len(result['accounts'])} accounts, no customer SCPs — only the default FullAWSAccess applies.",
            }
        )
    ou_ids = {o["id"] for o in result["organizational_units"]}
    # accounts are placed via parents; flag the org as flat if there are no non-root OUs
    non_root_ous = [o for o in result["organizational_units"] if not o.get("is_root")]
    if result["accounts"] and not non_root_ous:
        result["findings"].append(
            {
                "severity": "low",
                "title": "Flat organization (no OUs)",
                "detail": f"{len(result['accounts'])} accounts sit directly under the root with no OUs — no tiered guardrails.",
            }
        )

    result["status"] = "ok"
    result["discovery_envelope"] = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=(f"aws:organization/{result['org_id']}",) if result["org_id"] else (),
        permissions_used=_AWS_ORG_PERMISSIONS,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    ).to_dict()
    _ = ou_ids  # reserved for future account→OU placement enrichment
    return result


# ---------------------------------------------------------------------------
# Cross-account scan fan-out helpers (opt-in, read-only)
# ---------------------------------------------------------------------------


def org_fanout_enabled() -> bool:
    """Whether to fan a single scan across every member account of the org.

    Default OFF. Operators opt in by setting ``AGENT_BOM_AWS_ORG_INVENTORY``
    truthy, in addition to the base ``AGENT_BOM_AWS_INVENTORY`` gate. Symmetric
    with Azure's all-subscriptions and GCP's all-projects fan-out gates.
    """
    return os.environ.get(ORG_FANOUT_ENV_FLAG, "").strip().lower() in _TRUTHY


def max_accounts() -> int:
    """Defensive cap on the number of member accounts a single fan-out walks.

    Reads ``AGENT_BOM_AWS_MAX_ACCOUNTS`` (default 200); a non-positive or
    unparseable value falls back to the default so the cap can never disable
    bounding. Mirrors the GCP/Snowflake account caps.
    """
    raw = os.environ.get("AGENT_BOM_AWS_MAX_ACCOUNTS", "").strip()
    if not raw:
        return _DEFAULT_MAX_ACCOUNTS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_ACCOUNTS
    return value if value > 0 else _DEFAULT_MAX_ACCOUNTS


def list_member_account_ids(profile: str | None = None, *, force: bool = False) -> list[str]:
    """Return every ACTIVE member account id in the organization (read-only).

    The fan-out source for the AWS multi-account inventory and CIS benchmark.
    Enumerates the org via :func:`discover_organization` and keeps only accounts
    whose ``Status`` is ``ACTIVE`` (suspended/closed accounts cannot be assumed
    into and would only add noise). Returns ``[]`` for a standalone account (not
    in an org) or when the org cannot be read. Never raises.
    """
    org = discover_organization(profile=profile, force=force)
    if not isinstance(org, dict) or org.get("status") != "ok":
        return []
    account_ids: list[str] = []
    for acct in org.get("accounts", []) or []:
        if not isinstance(acct, dict):
            continue
        status = str(acct.get("status", "") or "").upper()
        if status and status != "ACTIVE":
            continue
        aid = str(acct.get("id", "") or "").strip()
        if aid and aid not in account_ids:
            account_ids.append(aid)
    return account_ids


def assume_account_session(
    account_id: str,
    *,
    profile: str | None = None,
    role_name: str | None = None,
    external_id: str | None = None,
    region: str | None = None,
    session_name: str = _ORG_SESSION_NAME,
    duration_seconds: int = 3600,
) -> Any:
    """Assume the read-only role in *account_id* and return a boto3 session.

    Keyless and short-lived: ``sts:AssumeRole`` from the management /
    delegated-admin account issues temporary credentials for the per-account
    read-only role, and the returned :class:`boto3.Session` is backed solely by
    those — no long-lived key is created or logged. The ExternalId (when set) is
    presented to satisfy the confused-deputy condition but never logged.

    Raises on failure (boto3 missing, AssumeRole denied) so the caller can skip
    the account with a warning rather than sinking the whole fan-out.
    """
    import boto3

    role = (role_name or os.environ.get(ORG_ROLE_NAME_ENV, "").strip() or _DEFAULT_ORG_ROLE_NAME).strip()
    ext = external_id if external_id is not None else os.environ.get(ORG_EXTERNAL_ID_ENV, "").strip()

    base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    sts = base.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role}"
    assume_kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "DurationSeconds": duration_seconds,
    }
    if ext:
        assume_kwargs["ExternalId"] = ext
    try:
        assumed = sts.assume_role(**assume_kwargs)
    finally:
        ext = ""  # drop the plaintext ExternalId reference immediately
    creds = assumed.get("Credentials", {})
    return boto3.Session(
        aws_access_key_id=creds.get("AccessKeyId"),
        aws_secret_access_key=creds.get("SecretAccessKey"),
        aws_session_token=creds.get("SessionToken"),
        region_name=region,
    )


def summarize_account_scan(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarise a multi-account fan-out into scanned / skipped / errored sets.

    Consumes the per-account inventory payloads
    :func:`agent_bom.cloud.aws_inventory.discover_all_account_inventories`
    returns. A ``status: "ok"`` payload counts as scanned; an
    ``"access_denied"`` payload (AssumeRole/read denied) as skipped; any other
    status (boto3 missing, unexpected error) as errored. Deterministic and
    JSON-serialisable so it can ride on the report's ``aws_organization`` block.
    """
    scanned: list[str] = []
    skipped: list[str] = []
    errored: list[str] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        aid = str(payload.get("account_id") or "").strip()
        status = str(payload.get("status", "") or "")
        if status == "ok":
            bucket = scanned
        elif status == "access_denied":
            bucket = skipped
        else:
            bucket = errored
        if aid:
            bucket.append(aid)
    return {
        "accounts_scanned": scanned,
        "accounts_skipped": skipped,
        "accounts_errored": errored,
        "total": len(scanned) + len(skipped) + len(errored),
    }


__all__ = [
    "INVENTORY_ENV_FLAG",
    "ORG_FANOUT_ENV_FLAG",
    "ORG_ROLE_NAME_ENV",
    "ORG_EXTERNAL_ID_ENV",
    "assume_account_session",
    "discover_organization",
    "list_member_account_ids",
    "max_accounts",
    "org_fanout_enabled",
    "summarize_account_scan",
]
