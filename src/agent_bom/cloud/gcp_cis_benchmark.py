"""CIS Google Cloud Platform Foundation Benchmark v3.0 — live project checks.

Runs read-only GCP API calls against the CIS GCP Foundation Benchmark v3.0
covering IAM, Logging, Networking, Virtual Machines, Storage, Cloud SQL,
and BigQuery.

Required roles (all read-only):
    roles/iam.securityReviewer
    roles/logging.viewer
    roles/compute.networkViewer
    roles/storage.objectViewer (for bucket IAM inspection)
    roles/bigquery.dataViewer (for BigQuery dataset inspection)

Required permissions for additional checks:
    compute.instances.list (CIS 4.1–4.9, 4.11)
    compute.subnetworks.list (CIS 3.9, 3.10)
    compute.firewalls.list (CIS 3.6–3.8)
    sqladmin.instances.list (CIS 6.1–6.7)
    logging.logMetrics.list (CIS 2.3–2.11)
    logging.sinks.list (CIS 2.2)
    dns.managedZones.list (CIS 2.12, 3.3–3.5)
    cloudkms.cryptoKeys.list (CIS 1.9–1.11)
    serviceusage.apiKeys.list (CIS 1.12–1.14)
    essentialcontacts.contacts.list (CIS 1.15)
    bigquery.datasets.list (CIS 7.1–7.3)

Authentication uses Application Default Credentials:
    gcloud auth application-default login
    or GOOGLE_APPLICATION_CREDENTIALS env var.

Install: ``pip install 'agent-bom[gcp]'``
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.security import sanitize_text

from .aws_cis_benchmark import CheckStatus, CISCheckResult, finalize_read_coverage  # noqa: F401 - facade re-export
from .aws_inventory import classify_project_disabled_error, is_access_denied_error  # noqa: F401 - facade re-export
from .base import CloudDiscoveryError
from .gcp_cis._base import (  # noqa: F401 - facade re-export
    _BIGQUERY_SECTION,
    _COMPUTE_SECTION,
    _CTX,
    _IAM_SECTION,
    _LOGGING_SECTION,
    _NETWORK_SECTION,
    _SQL_SECTION,
    _STORAGE_SECTION,
    GCPCISReport,
    _clear_credentials,
    _CredentialContext,
    _creds_kwargs,
    _ctx,
    _discovery_client,
    _gcp_bigquery_datasets,
    _gcp_cloud_sql_instances,
    _gcp_kms_crypto_keys,
    _gcp_managed_zones,
    _gcp_paginate_list,
    _import_google_cloud_module,
    _set_credentials,
)
from .gcp_cis.bigquery import (  # noqa: F401 - facade re-export
    _check_7_1,
    _check_7_2,
    _check_7_3,
)
from .gcp_cis.cloudsql import (  # noqa: F401 - facade re-export
    _check_6_1,
    _check_6_2,
    _check_6_3,
    _check_6_4,
    _check_6_5,
    _check_6_6,
    _check_6_7,
)
from .gcp_cis.compute import (  # noqa: F401 - facade re-export
    _check_4_1,
    _check_4_2,
    _check_4_3,
    _check_4_4,
    _check_4_5,
    _check_4_6,
    _check_4_7,
    _check_4_8,
    _check_4_9,
    _check_4_11,
)
from .gcp_cis.iam import (  # noqa: F401 - facade re-export
    _check_1_1,
    _check_1_2,
    _check_1_3,
    _check_1_4,
    _check_1_5,
    _check_1_6,
    _check_1_7,
    _check_1_8,
)
from .gcp_cis.iam_keys import (  # noqa: F401 - facade re-export
    _check_1_9,
    _check_1_10,
    _check_1_11,
    _check_1_12,
    _check_1_13,
    _check_1_14,
    _check_1_15,
)
from .gcp_cis.logging_checks import (  # noqa: F401 - facade re-export
    _check_2_1,
    _check_2_2,
    _check_2_3,
    _check_2_4,
    _check_2_5,
    _check_2_6,
    _check_2_7,
    _check_2_8,
    _check_2_9,
    _check_2_10,
    _check_2_11,
    _check_2_12,
)
from .gcp_cis.networking import (  # noqa: F401 - facade re-export
    _check_3_1,
    _check_3_2,
    _check_3_3,
    _check_3_4,
    _check_3_5,
    _check_3_6,
    _check_3_7,
    _check_3_8,
    _check_3_9,
    _check_3_10,
)
from .gcp_cis.runner import CHECK_REGISTRY, run_registered_checks  # noqa: F401 - facade re-export
from .gcp_cis.storage import (  # noqa: F401 - facade re-export
    _check_5_1,
    _check_5_2,
)

try:
    from .normalization import sanitize_discovery_warning
except Exception:  # pragma: no cover - normalization always present in practice

    def sanitize_discovery_warning(value: Any, *, max_len: int = 500) -> str:  # type: ignore[misc]
        return str(value)[:max_len]


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    project_id: str | None = None,
    credentials: Any = None,
    checks: list[str] | None = None,
) -> GCPCISReport:
    """Run CIS GCP Foundation Benchmark v3.0 checks.

    Args:
        project_id: GCP project ID. Falls back to GOOGLE_CLOUD_PROJECT env var.
        credentials: Optional google-auth credential threaded into every check's
            service client. When ``None`` the SDK falls back to Application
            Default Credentials (the prior behaviour). Pass an explicit
            credential (e.g. ``google.oauth2.credentials.Credentials``) to run
            against a project without ambient ADC.
        checks: Optional list of check IDs to run (e.g. ['1.5', '3.6']).
            Runs all checks if omitted.

    Returns:
        GCPCISReport with pass/fail results for each check.

    Raises:
        CloudDiscoveryError: if no GCP SDK packages are installed.
    """
    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not resolved_project:
        raise CloudDiscoveryError("GCP project ID required. Set GOOGLE_CLOUD_PROJECT env var or pass project_id.")

    # Verify at least one GCP SDK is importable
    _has_sdk = False
    for mod in ("google.cloud.compute_v1", "google.cloud.logging_v2", "google.cloud.storage", "googleapiclient"):
        try:
            __import__(mod)
            _has_sdk = True
            break
        except ImportError:
            continue

    if not _has_sdk:
        raise CloudDiscoveryError("At least one GCP SDK is required. Install with: pip install 'agent-bom[gcp]'")

    report = GCPCISReport(project_id=resolved_project)

    # Thread the resolved credential to every check's client factory for the
    # duration of this (sequential) run. Cleared in the finally block below so a
    # subsequent ADC-only run is not contaminated by a prior explicit credential.
    _set_credentials(credentials)
    try:
        run_registered_checks(report, resolved_project, checks)
    finally:
        _clear_credentials()

    # Structured remediation per #665.
    from agent_bom.cloud.cis_remediation import attach_all

    attach_all(report, cloud="gcp")

    return report


# Bounded concurrency for the multi-project fan-out — mirrors the GCP inventory
# fan-out's thread pool. Each thread sets its own credential context (the context
# is thread-local), so concurrent per-project runs do not contaminate one another.
_MAX_CIS_FANOUT_WORKERS = 8


def run_all_project_benchmarks(
    credentials: Any = None,
    checks: list[str] | None = None,
) -> GCPCISReport:
    """Run the CIS GCP benchmark for EVERY project in the org/folder tree.

    The CIS counterpart of :func:`agent_bom.cloud.gcp_inventory.discover_all_project_inventories`:
    it reuses the same project enumeration
    (:func:`agent_bom.cloud.gcp_organizations.list_project_ids`) and the same
    read-only impersonation resolution
    (:func:`agent_bom.cloud.gcp_inventory._resolve_impersonation`) so the
    benchmark covers the identical estate the inventory fan-out does. Each
    project is benchmarked concurrently (bounded thread pool) and the
    per-project results are aggregated into one :class:`GCPCISReport` with every
    check tagged by its ``project_id``.

    Read-only and partial-permission tolerant: a project the credential cannot
    read is skipped with a warning rather than failing the whole run.

    Raises:
        CloudDiscoveryError: if no GCP SDK packages are installed and a project
            set cannot be resolved.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from agent_bom.cloud import gcp_inventory, gcp_organizations

    warnings: list[str] = []
    resolved = gcp_inventory._resolve_impersonation(credentials, warnings)

    try:
        project_ids = gcp_organizations.list_project_ids(resolved, force=True)
    except Exception as exc:  # noqa: BLE001 — org enumeration failure must degrade, not crash
        logger.warning("GCP org project enumeration failed: %s", sanitize_text(sanitize_discovery_warning(exc)))
        warnings.append(sanitize_discovery_warning(exc))
        project_ids = []

    if not project_ids:
        single = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
        project_ids = [single] if single else []
    if not project_ids:
        raise CloudDiscoveryError(
            "No GCP projects resolved for the multi-project CIS benchmark. Grant org/folder browse access or set GOOGLE_CLOUD_PROJECT."
        )

    aggregate = GCPCISReport(project_id=", ".join(project_ids))
    aggregate.warnings.extend(warnings)

    def _run_one(project_id: str) -> tuple[str, GCPCISReport]:
        return project_id, run_benchmark(project_id=project_id, credentials=resolved, checks=checks)

    # Deterministic aggregation: collect per-project reports keyed by id, then
    # merge in enumeration order so output is stable across runs.
    reports: dict[str, GCPCISReport] = {}
    with ThreadPoolExecutor(max_workers=min(_MAX_CIS_FANOUT_WORKERS, len(project_ids))) as executor:
        future_to_project = {executor.submit(_run_one, pid): pid for pid in project_ids}
        for future in as_completed(future_to_project):
            pid = future_to_project[future]
            try:
                _pid, project_report = future.result()
                reports[pid] = project_report
            except Exception as exc:  # noqa: BLE001 — one unreadable project must not sink the rest
                aggregate.warnings.append(f"Project {pid} skipped: {sanitize_discovery_warning(exc)}")

    for pid in project_ids:
        merged = reports.get(pid)
        if merged is None:
            continue
        aggregate.projects_scanned.append(pid)
        for check in merged.checks:
            check.account_id = pid
            aggregate.checks.append(check)
        aggregate.warnings.extend(merged.warnings)

    return aggregate
