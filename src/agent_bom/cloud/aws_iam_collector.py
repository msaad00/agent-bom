"""Bounded collection of AWS IAM role policy and usage evidence."""

from __future__ import annotations

import time
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, Mapping

from agent_bom.cloud.aws_iam_evidence import (
    EvidenceCompleteness,
    IamPrincipalEvidence,
    IamRoleUsageEvidence,
    IamServiceUsageEvidence,
    NormalizedIamPolicy,
    UsageEvidenceState,
    normalize_iam_policy_document,
)

_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
_UNSUPPORTED_CODES = {"NotSupported", "NotSupportedException", "UnsupportedOperation"}
_ACCESS_ADVISOR_PAGE_SIZE = 100
_ACCESS_ADVISOR_HARD_MAX_POLLS = 10
_ACCESS_ADVISOR_HARD_MAX_PAGES = 10
_ACCESS_ADVISOR_INITIAL_BACKOFF_SECONDS = 1.0
_ACCESS_ADVISOR_MAX_BACKOFF_SECONDS = 5.0


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


def _usage_failure(exc: Exception) -> tuple[UsageEvidenceState, str]:
    code = _error_code(exc)
    if code in _DENIED_CODES:
        return UsageEvidenceState.ACCESS_DENIED, "access_advisor_denied"
    if code in _UNSUPPORTED_CODES:
        return UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
    return UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"


def _collect_access_advisor(
    client: Any,
    principal_arn: str,
    *,
    max_polls: int,
    max_pages: int,
    collected_at: datetime,
) -> tuple[tuple[IamServiceUsageEvidence, ...], UsageEvidenceState, str]:
    try:
        started = client.generate_service_last_accessed_details(Arn=principal_arn, Granularity="SERVICE_LEVEL")
        job_id = started.get("JobId")
        if not isinstance(job_id, str) or not job_id:
            return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
        response: Mapping[str, Any] = {}
        poll_budget = min(_ACCESS_ADVISOR_HARD_MAX_POLLS, max(1, max_polls))
        for poll_index in range(poll_budget):
            candidate = client.get_service_last_accessed_details(JobId=job_id, MaxItems=_ACCESS_ADVISOR_PAGE_SIZE)
            if not isinstance(candidate, Mapping):
                return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
            response = candidate
            if response.get("JobStatus") == "COMPLETED":
                break
            if response.get("JobStatus") == "FAILED":
                return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
            if poll_index + 1 < poll_budget:
                delay = min(
                    _ACCESS_ADVISOR_INITIAL_BACKOFF_SECONDS * (2**poll_index),
                    _ACCESS_ADVISOR_MAX_BACKOFF_SECONDS,
                )
                time.sleep(delay)
        else:
            return (), UsageEvidenceState.PENDING, "access_advisor_pending"

        return _completed_access_advisor_evidence(
            client,
            job_id,
            response,
            max_pages=max_pages,
            collected_at=collected_at,
        )
    except Exception as exc:
        state, diagnostic = _usage_failure(exc)
        return (), state, diagnostic


def _completed_access_advisor_evidence(
    client: Any,
    job_id: str,
    response: Mapping[str, Any],
    *,
    max_pages: int,
    collected_at: datetime,
) -> tuple[tuple[IamServiceUsageEvidence, ...], UsageEvidenceState, str]:
    """Read every page of one completed job without retaining partial output."""
    pages: list[Mapping[str, Any]] = [response]
    page_budget = min(_ACCESS_ADVISOR_HARD_MAX_PAGES, max(1, max_pages))
    while bool(pages[-1].get("IsTruncated")):
        if len(pages) >= page_budget:
            return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_page_budget_exhausted"
        marker = pages[-1].get("Marker")
        if not isinstance(marker, str) or not marker:
            return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
        candidate = client.get_service_last_accessed_details(
            JobId=job_id,
            MaxItems=_ACCESS_ADVISOR_PAGE_SIZE,
            Marker=marker,
        )
        if not isinstance(candidate, Mapping) or candidate.get("JobStatus") not in {None, "COMPLETED"}:
            return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
        pages.append(candidate)

    evidence: list[IamServiceUsageEvidence] = []
    for page in pages:
        services = page.get("ServicesLastAccessed", [])
        if not isinstance(services, list):
            return (), UsageEvidenceState.UNAVAILABLE, "access_advisor_unavailable"
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
                    collected_at=collected_at,
                )
            )
    return tuple(evidence), UsageEvidenceState.AVAILABLE, "access_advisor_available"


def _usage_result(
    client: Any,
    *,
    principal_arn: str,
    role_name: str,
    role_snapshot: Mapping[str, Any] | None,
    usage: tuple[IamServiceUsageEvidence, ...],
    usage_state: UsageEvidenceState,
    diagnostic: str,
    collected_at: datetime,
) -> IamRoleUsageEvidence:
    role_usage = _role_last_used(
        client,
        role_name,
        role_snapshot=role_snapshot,
        collected_at=collected_at,
    )
    if role_usage is not None:
        usage = (*usage, role_usage)
    return IamRoleUsageEvidence(
        principal_arn=principal_arn,
        usage_state=usage_state,
        records=usage,
        diagnostic=diagnostic,
        collected_at=collected_at,
    )


def collect_iam_roles_usage_evidence(
    client: Any,
    roles: Sequence[tuple[str, str, Mapping[str, Any] | None]],
    *,
    max_access_advisor_polls: int = 3,
    max_access_advisor_pages: int = 5,
    collected_at: datetime | None = None,
) -> dict[str, IamRoleUsageEvidence]:
    """Collect several roles using shared, bounded Access Advisor poll rounds.

    Access Advisor jobs are asynchronous. Starting and immediately polling one
    role at a time makes the default three polls collapse into one instant and
    usually returns ``pending`` for every role. This method starts the bounded
    estate batch first, then polls all jobs in shared exponential-backoff rounds,
    so waiting is once per estate rather than once per role.
    """
    observed_at = collected_at or datetime.now(timezone.utc)
    results: dict[str, IamRoleUsageEvidence] = {}
    jobs: dict[str, tuple[str, str, Mapping[str, Any] | None]] = {}
    for principal_arn, role_name, role_snapshot in roles:
        try:
            started = client.generate_service_last_accessed_details(
                Arn=principal_arn,
                Granularity="SERVICE_LEVEL",
            )
            job_id = started.get("JobId")
            if not isinstance(job_id, str) or not job_id:
                raise ValueError("missing Access Advisor job id")
            jobs[principal_arn] = (job_id, role_name, role_snapshot)
        except Exception as exc:
            state, diagnostic = _usage_failure(exc)
            results[principal_arn] = _usage_result(
                client,
                principal_arn=principal_arn,
                role_name=role_name,
                role_snapshot=role_snapshot,
                usage=(),
                usage_state=state,
                diagnostic=diagnostic,
                collected_at=observed_at,
            )

    poll_budget = min(_ACCESS_ADVISOR_HARD_MAX_POLLS, max(1, max_access_advisor_polls))
    for poll_index in range(poll_budget):
        for principal_arn, (job_id, role_name, role_snapshot) in tuple(jobs.items()):
            try:
                response = client.get_service_last_accessed_details(
                    JobId=job_id,
                    MaxItems=_ACCESS_ADVISOR_PAGE_SIZE,
                )
                if not isinstance(response, Mapping):
                    raise TypeError("invalid Access Advisor response")
                status = str(response.get("JobStatus") or "").upper()
                if status == "COMPLETED":
                    usage, state, diagnostic = _completed_access_advisor_evidence(
                        client,
                        job_id,
                        response,
                        max_pages=max_access_advisor_pages,
                        collected_at=observed_at,
                    )
                    results[principal_arn] = _usage_result(
                        client,
                        principal_arn=principal_arn,
                        role_name=role_name,
                        role_snapshot=role_snapshot,
                        usage=usage,
                        usage_state=state,
                        diagnostic=diagnostic,
                        collected_at=observed_at,
                    )
                    del jobs[principal_arn]
                elif status == "FAILED":
                    results[principal_arn] = _usage_result(
                        client,
                        principal_arn=principal_arn,
                        role_name=role_name,
                        role_snapshot=role_snapshot,
                        usage=(),
                        usage_state=UsageEvidenceState.UNAVAILABLE,
                        diagnostic="access_advisor_unavailable",
                        collected_at=observed_at,
                    )
                    del jobs[principal_arn]
                elif status not in {"IN_PROGRESS", "RUNNING", "PENDING"}:
                    raise ValueError("unknown Access Advisor job status")
            except Exception as exc:
                state, diagnostic = _usage_failure(exc)
                results[principal_arn] = _usage_result(
                    client,
                    principal_arn=principal_arn,
                    role_name=role_name,
                    role_snapshot=role_snapshot,
                    usage=(),
                    usage_state=state,
                    diagnostic=diagnostic,
                    collected_at=observed_at,
                )
                del jobs[principal_arn]

        if not jobs or poll_index + 1 >= poll_budget:
            break
        delay = min(
            _ACCESS_ADVISOR_INITIAL_BACKOFF_SECONDS * (2**poll_index),
            _ACCESS_ADVISOR_MAX_BACKOFF_SECONDS,
        )
        time.sleep(delay)

    for principal_arn, (_job_id, role_name, role_snapshot) in jobs.items():
        results[principal_arn] = _usage_result(
            client,
            principal_arn=principal_arn,
            role_name=role_name,
            role_snapshot=role_snapshot,
            usage=(),
            usage_state=UsageEvidenceState.PENDING,
            diagnostic="access_advisor_pending",
            collected_at=observed_at,
        )
    return results


def _role_last_used(
    client: Any,
    role_name: str,
    *,
    role_snapshot: Mapping[str, Any] | None,
    collected_at: datetime,
) -> IamServiceUsageEvidence | None:
    # AWS ListRoles intentionally omits RoleLastUsed. Reuse a richer caller
    # snapshot only when it actually contains that field; otherwise GetRole is
    # required to avoid turning missing telemetry into a false "never used".
    if role_snapshot is None or "RoleLastUsed" not in role_snapshot:
        try:
            response = client.get_role(RoleName=role_name)
        except Exception:
            return None
        role = response.get("Role", {})
    else:
        role = role_snapshot
    last_used = role.get("RoleLastUsed") if isinstance(role, Mapping) else None
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
        collected_at=collected_at,
    )


def collect_iam_role_usage_evidence(
    client: Any,
    *,
    principal_arn: str,
    role_name: str,
    role_snapshot: Mapping[str, Any] | None = None,
    max_access_advisor_polls: int = 3,
    max_access_advisor_pages: int = 5,
    collected_at: datetime | None = None,
) -> IamRoleUsageEvidence:
    """Collect usage facts only, with fixed poll/page budgets.

    This entry point intentionally performs no policy-list or policy-document
    calls. Inventory already owns those reads. A caller may supply a richer
    ``role_snapshot`` that already contains ``RoleLastUsed``; ordinary
    ``ListRoles`` snapshots omit it, so the collector falls back to ``GetRole``.
    """
    observed_at = collected_at or datetime.now(timezone.utc)
    usage, usage_state, diagnostic = _collect_access_advisor(
        client,
        principal_arn,
        max_polls=max_access_advisor_polls,
        max_pages=max_access_advisor_pages,
        collected_at=observed_at,
    )
    role_usage = _role_last_used(
        client,
        role_name,
        role_snapshot=role_snapshot,
        collected_at=observed_at,
    )
    if role_usage is not None:
        usage = (*usage, role_usage)
    return IamRoleUsageEvidence(
        principal_arn=principal_arn,
        usage_state=usage_state,
        records=usage,
        diagnostic=diagnostic,
        collected_at=observed_at,
    )


def collect_iam_role_evidence(
    client: Any,
    *,
    principal_arn: str,
    role_name: str,
    max_access_advisor_polls: int = 3,
    max_access_advisor_pages: int = 5,
) -> IamPrincipalEvidence:
    """Collect policy and usage facts without interpreting authorization."""
    policies, policy_state = _collect_policies(client, role_name)

    usage_evidence = collect_iam_role_usage_evidence(
        client,
        principal_arn=principal_arn,
        role_name=role_name,
        max_access_advisor_polls=max_access_advisor_polls,
        max_access_advisor_pages=max_access_advisor_pages,
    )
    return IamPrincipalEvidence(
        principal_arn=principal_arn,
        policies=policies,
        usage=usage_evidence.records,
        policy_completeness=policy_state,
        usage_state=usage_evidence.usage_state,
    )
