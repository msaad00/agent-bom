"""Bounded collection of AWS IAM role policy and usage evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from agent_bom.cloud.aws_iam_evidence import (
    EvidenceCompleteness,
    IamPrincipalEvidence,
    IamServiceUsageEvidence,
    NormalizedIamPolicy,
    UsageEvidenceState,
    normalize_iam_policy_document,
)

_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
_UNSUPPORTED_CODES = {"NotSupported", "NotSupportedException", "UnsupportedOperation"}


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return ""
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return ""
    code = error.get("Code")
    return code if isinstance(code, str) else ""


def _unavailable_policy(diagnostic: str, *, arn: str | None = None) -> NormalizedIamPolicy:
    return NormalizedIamPolicy(
        version=None,
        statements=(),
        completeness=EvidenceCompleteness.UNAVAILABLE,
        diagnostics=(diagnostic,),
        source_policy_arn=arn,
    )


def _pages(client: Any, operation: str, **kwargs: str) -> list[Mapping[str, Any]]:
    paginator = client.get_paginator(operation)
    return [page for page in paginator.paginate(**kwargs) if isinstance(page, Mapping)]


def _collect_policies(client: Any, role_name: str) -> tuple[tuple[NormalizedIamPolicy, ...], EvidenceCompleteness]:
    policies: list[NormalizedIamPolicy] = []
    collection_failed = False
    try:
        for page in _pages(client, "list_attached_role_policies", RoleName=role_name):
            entries = page.get("AttachedPolicies", [])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                arn = entry.get("PolicyArn")
                if not isinstance(arn, str) or not arn:
                    policies.append(_unavailable_policy("attached_policy_missing_arn"))
                    continue
                try:
                    metadata = client.get_policy(PolicyArn=arn).get("Policy", {})
                    version_id = metadata.get("DefaultVersionId") if isinstance(metadata, Mapping) else None
                    if not isinstance(version_id, str) or not version_id:
                        policies.append(_unavailable_policy("attached_policy_missing_default_version", arn=arn))
                        continue
                    version = client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                    payload = version.get("PolicyVersion", {})
                    document = payload.get("Document") if isinstance(payload, Mapping) else None
                    policies.append(normalize_iam_policy_document(document, source_policy_arn=arn))
                except Exception:
                    collection_failed = True
                    policies.append(_unavailable_policy("attached_policy_read_failed", arn=arn))
    except Exception:
        collection_failed = True
        policies.append(_unavailable_policy("attached_policy_list_failed"))

    try:
        for page in _pages(client, "list_role_policies", RoleName=role_name):
            names = page.get("PolicyNames", [])
            if not isinstance(names, list):
                continue
            for name in names:
                if not isinstance(name, str) or not name:
                    continue
                try:
                    response = client.get_role_policy(RoleName=role_name, PolicyName=name)
                    policies.append(normalize_iam_policy_document(response.get("PolicyDocument")))
                except Exception:
                    collection_failed = True
                    policies.append(_unavailable_policy("inline_policy_read_failed"))
    except Exception:
        collection_failed = True
        policies.append(_unavailable_policy("inline_policy_list_failed"))
    if collection_failed:
        state = EvidenceCompleteness.PARTIAL if any(policy.statements for policy in policies) else EvidenceCompleteness.UNAVAILABLE
    elif any(policy.completeness is not EvidenceCompleteness.COMPLETE for policy in policies):
        state = EvidenceCompleteness.PARTIAL
    else:
        # Successful empty policy lists are complete evidence: the role has no
        # attached or inline identity policies.
        state = EvidenceCompleteness.COMPLETE
    return tuple(policies), state


def _usage_failure(exc: Exception) -> UsageEvidenceState:
    code = _error_code(exc)
    if code in _DENIED_CODES:
        return UsageEvidenceState.ACCESS_DENIED
    if code in _UNSUPPORTED_CODES:
        return UsageEvidenceState.NOT_SUPPORTED
    return UsageEvidenceState.UNAVAILABLE


def _collect_access_advisor(
    client: Any, principal_arn: str, *, max_polls: int
) -> tuple[tuple[IamServiceUsageEvidence, ...], UsageEvidenceState]:
    try:
        started = client.generate_service_last_accessed_details(Arn=principal_arn, Granularity="SERVICE_LEVEL")
        job_id = started.get("JobId")
        if not isinstance(job_id, str) or not job_id:
            return (), UsageEvidenceState.UNAVAILABLE
        response: Mapping[str, Any] = {}
        for _ in range(max(1, max_polls)):
            candidate = client.get_service_last_accessed_details(JobId=job_id)
            if not isinstance(candidate, Mapping):
                return (), UsageEvidenceState.UNAVAILABLE
            response = candidate
            if response.get("JobStatus") == "COMPLETED":
                break
            if response.get("JobStatus") == "FAILED":
                return (), UsageEvidenceState.UNAVAILABLE
        else:
            return (), UsageEvidenceState.PENDING
        services = response.get("ServicesLastAccessed", [])
        if not isinstance(services, list):
            return (), UsageEvidenceState.UNAVAILABLE
        evidence: list[IamServiceUsageEvidence] = []
        for service in services:
            if not isinstance(service, Mapping):
                continue
            namespace = service.get("ServiceNamespace")
            if not isinstance(namespace, str) or not namespace:
                continue
            accessed = service.get("LastAuthenticated")
            region = service.get("LastAuthenticatedRegion")
            evidence.append(
                IamServiceUsageEvidence(
                    service_namespace=namespace,
                    state=UsageEvidenceState.AVAILABLE,
                    last_accessed_at=accessed if isinstance(accessed, datetime) else None,
                    last_accessed_region=region if isinstance(region, str) else None,
                )
            )
        return tuple(evidence), UsageEvidenceState.AVAILABLE
    except Exception as exc:
        return (), _usage_failure(exc)


def _role_last_used(client: Any, role_name: str) -> IamServiceUsageEvidence | None:
    try:
        response = client.get_role(RoleName=role_name)
    except Exception:
        return None
    role = response.get("Role", {})
    last_used = role.get("RoleLastUsed", {}) if isinstance(role, Mapping) else {}
    if not isinstance(last_used, Mapping):
        return None
    accessed = last_used.get("LastUsedDate")
    region = last_used.get("Region")
    return IamServiceUsageEvidence(
        service_namespace="*",
        state=UsageEvidenceState.AVAILABLE,
        last_accessed_at=accessed if isinstance(accessed, datetime) else None,
        last_accessed_region=region if isinstance(region, str) else None,
        source="role_last_used",
    )


def collect_iam_role_evidence(
    client: Any,
    *,
    principal_arn: str,
    role_name: str,
    max_access_advisor_polls: int = 3,
) -> IamPrincipalEvidence:
    """Collect policy and usage facts without interpreting authorization."""
    policies, policy_state = _collect_policies(client, role_name)

    usage, usage_state = _collect_access_advisor(client, principal_arn, max_polls=max_access_advisor_polls)
    role_usage = _role_last_used(client, role_name)
    if role_usage is not None:
        usage = (*usage, role_usage)
    return IamPrincipalEvidence(
        principal_arn=principal_arn,
        policies=policies,
        usage=usage,
        policy_completeness=policy_state,
        usage_state=usage_state,
    )
