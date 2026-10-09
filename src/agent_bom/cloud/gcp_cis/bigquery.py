"""CIS GCP 7.x: BigQuery dataset access and encryption."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _BIGQUERY_SECTION,
    _gcp_bigquery_datasets,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_7_1(project_id: str) -> CISCheckResult:
    """CIS 7.1 — Ensure BigQuery datasets are not anonymously or publicly accessible."""
    result = CISCheckResult(
        check_id="7.1",
        title="BigQuery datasets not publicly accessible",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove allUsers and allAuthenticatedUsers from BigQuery dataset IAM policies.",
        cis_section=_BIGQUERY_SECTION,
    )
    try:
        bq = _seams()._discovery_client("bigquery", "v2")
        datasets = _gcp_bigquery_datasets(bq, project_id)

        public_datasets: list[str] = []
        for ds in datasets:
            ds_ref = ds.get("datasetReference", {})
            ds_id = ds_ref.get("datasetId", "unknown")
            ds_detail = bq.datasets().get(projectId=project_id, datasetId=ds_id).execute()
            access = ds_detail.get("access", [])
            for entry in access:
                special_group = entry.get("specialGroup", "")
                iam_member = entry.get("iamMember", "")
                if special_group in ("allUsers", "allAuthenticatedUsers") or iam_member in ("allUsers", "allAuthenticatedUsers"):
                    public_datasets.append(ds_id)
                    break

        if public_datasets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Publicly accessible BigQuery datasets: {', '.join(public_datasets[:10])}"
            result.resource_ids = public_datasets
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No BigQuery datasets are publicly accessible across {len(datasets)} dataset(s)."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check BigQuery dataset access: {sanitize_discovery_warning(exc)}"
    return result


def _check_7_2(project_id: str) -> CISCheckResult:
    """CIS 7.2 — Ensure BigQuery datasets have default table expiration configured."""
    result = CISCheckResult(
        check_id="7.2",
        title="Default CMEK specified for BigQuery datasets",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set a default table expiration on all BigQuery datasets to automatically clean up unused tables.",
        cis_section=_BIGQUERY_SECTION,
    )
    try:
        bq = _seams()._discovery_client("bigquery", "v2")
        datasets = _gcp_bigquery_datasets(bq, project_id)

        failing: list[str] = []
        for ds in datasets:
            ds_ref = ds.get("datasetReference", {})
            ds_id = ds_ref.get("datasetId", "unknown")
            ds_detail = bq.datasets().get(projectId=project_id, datasetId=ds_id).execute()
            expiration = ds_detail.get("defaultTableExpirationMs")
            if not expiration:
                failing.append(ds_id)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = (
                f"BigQuery datasets without default table expiration ({len(failing)}/{len(datasets)}): {', '.join(failing[:10])}"
            )
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(datasets)} BigQuery dataset(s) have default table expiration configured."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check BigQuery dataset expiration: {sanitize_discovery_warning(exc)}"
    return result


def _check_7_3(project_id: str) -> CISCheckResult:
    """CIS 7.3 — Ensure BigQuery datasets are encrypted with Customer-Managed Keys (CMK)."""
    result = CISCheckResult(
        check_id="7.3",
        title="BigQuery tables encrypted with CMEK",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set a default KMS key on all BigQuery datasets so that new tables are automatically encrypted with CMEK.",
        cis_section=_BIGQUERY_SECTION,
    )
    try:
        bq = _seams()._discovery_client("bigquery", "v2")
        datasets = _gcp_bigquery_datasets(bq, project_id)

        failing: list[str] = []
        for ds in datasets:
            ds_ref = ds.get("datasetReference", {})
            ds_id = ds_ref.get("datasetId", "unknown")
            ds_detail = bq.datasets().get(projectId=project_id, datasetId=ds_id).execute()
            default_encryption = ds_detail.get("defaultEncryptionConfiguration", {})
            if not default_encryption or not default_encryption.get("kmsKeyName"):
                failing.append(ds_id)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"BigQuery datasets without CMEK encryption ({len(failing)}/{len(datasets)}): {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(datasets)} BigQuery dataset(s) are encrypted with CMEK."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed. Install with: pip install google-api-python-client"
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check BigQuery dataset encryption: {sanitize_discovery_warning(exc)}"
    return result
