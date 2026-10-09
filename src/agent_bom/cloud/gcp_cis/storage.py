"""CIS GCP 5.x: Cloud Storage bucket access."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage
from agent_bom.cloud.aws_inventory import classify_project_disabled_error, is_access_denied_error
from agent_bom.cloud.normalization import sanitize_discovery_warning
from agent_bom.security import sanitize_text

from ._base import (
    _STORAGE_SECTION,
    _creds_kwargs,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_5_1(project_id: str) -> CISCheckResult:
    """CIS 5.1 — Ensure Cloud Storage buckets are not publicly accessible."""
    result = CISCheckResult(
        check_id="5.1",
        title="Cloud Storage buckets not publicly accessible",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        storage = _seams()._import_google_cloud_module("storage")

        client = storage.Client(project=project_id, **_creds_kwargs())
        public_buckets: list[str] = []
        inspected = 0
        denied: list[str] = []
        unavailable: dict[str, list[str]] = {}

        for bucket in client.list_buckets():
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                inspected += 1
                for binding in policy.bindings:
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_buckets.append(bucket.name)
                        break
            except Exception as exc:
                cause = classify_project_disabled_error(exc)
                if cause:
                    unavailable.setdefault(cause, []).append(bucket.name)
                elif is_access_denied_error(exc):
                    denied.append(bucket.name)
                else:
                    unavailable.setdefault("unavailable", []).append(bucket.name)
                logger.debug("Could not check IAM policy for bucket %s: %s", bucket.name, sanitize_text(exc))

        if public_buckets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Publicly accessible buckets: {', '.join(public_buckets[:10])}"
            result.resource_ids = public_buckets
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            unavailable=unavailable,
            permission="storage.buckets.getIamPolicy",
            resource_kind="bucket",
            pass_evidence="No buckets with public (allUsers/allAuthenticatedUsers) IAM bindings found.",
        )
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-storage not installed. Install with: pip install google-cloud-storage"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Cloud Storage buckets: {sanitize_discovery_warning(exc)}"
    return result


def _check_5_2(project_id: str) -> CISCheckResult:
    """CIS 5.2 — Ensure that Cloud Storage buckets have uniform bucket-level access enabled."""
    result = CISCheckResult(
        check_id="5.2",
        title="Uniform bucket-level access enabled on buckets",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable uniform bucket-level access on all Cloud Storage buckets to use IAM exclusively for access control.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        storage = _seams()._import_google_cloud_module("storage")

        client = storage.Client(project=project_id, **_creds_kwargs())
        failing: list[str] = []
        total = 0

        for bucket in client.list_buckets():
            total += 1
            iam_config = bucket.iam_configuration
            if not iam_config.uniform_bucket_level_access_enabled:
                failing.append(bucket.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Buckets without uniform access ({len(failing)}/{total}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} bucket(s) have uniform bucket-level access enabled."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-cloud-storage not installed. Install with: pip install google-cloud-storage"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check bucket uniform access: {sanitize_discovery_warning(exc)}"
    return result
