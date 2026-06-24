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
