"""Shared models, credential threading and client helpers for the GCP CIS benchmark."""

from __future__ import annotations

import importlib
import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")

_FACADE = "agent_bom.cloud.gcp_cis_benchmark"


def _seams() -> Any:
    """Return the public facade module.

    Tests and callers patch client factories and checks on
    ``agent_bom.cloud.gcp_cis_benchmark``; resolving them through the facade at
    call time keeps those patch points steering the split modules.
    """
    return importlib.import_module(_FACADE)


def _import_google_cloud_module(module: str) -> Any:
    """Import optional Google Cloud SDK modules without requiring mypy stubs."""
    return importlib.import_module(f"google.cloud.{module}")


# ---------------------------------------------------------------------------
# Credential threading
# ---------------------------------------------------------------------------
#
# CIS checks build their own service clients inline. AWS/Azure CIS thread an
# explicit credential into every client; GCP must do the same so the benchmark
# works when called with an explicit credential (or no ambient ADC). The runner
# stores the resolved credential in a module-local context for the duration of a
# (sequential) benchmark run, and the client factories below pick it up. When no
# credential is supplied the factories pass nothing, so the SDK falls back to
# Application Default Credentials exactly as before.


@dataclass
class _CredentialContext:
    """Thread-local-ish holder for the credential threaded through a run."""

    credentials: Any = None


_CTX = threading.local()


def _ctx() -> _CredentialContext:
    ctx = getattr(_CTX, "value", None)
    if ctx is None:
        ctx = _CredentialContext()
        _CTX.value = ctx
    return ctx


def _set_credentials(credentials: Any) -> None:
    _ctx().credentials = credentials


def _clear_credentials() -> None:
    _ctx().credentials = None


def _creds_kwargs() -> dict[str, Any]:
    """Return ``{"credentials": ...}`` when a credential is threaded, else ``{}``.

    Passing an empty dict preserves the ADC fallback behaviour for callers that
    do not supply an explicit credential.
    """
    creds = _ctx().credentials
    return {"credentials": creds} if creds is not None else {}


def _discovery_client(service: str, version: str) -> Any:
    """Build a googleapiclient discovery client threading the run credential."""
    import googleapiclient.discovery

    return googleapiclient.discovery.build(service, version, cache_discovery=False, **_creds_kwargs())


def _gcp_paginate_list(resource_api: Any, items_key: str, **list_kwargs: Any) -> list[dict]:
    """Collect all pages from a googleapiclient ``*.list`` resource.

    Stops when ``list_next`` returns ``None`` or when the response has no
    string page token. MagicMock stubs that omit ``list_next = None`` used to
    hang forever because MagickMock is truthy — require an explicit string
    token before advancing.
    """
    items: list[dict] = []
    request = resource_api.list(**list_kwargs)
    seen_requests: set[int] = set()
    while request is not None:
        request_id = id(request)
        if request_id in seen_requests:
            break
        seen_requests.add(request_id)
        response = request.execute()
        if not isinstance(response, dict):
            break
        items.extend(response.get(items_key, []) or [])
        next_token = response.get("nextPageToken") or response.get("pageToken")
        if not isinstance(next_token, str) or not next_token.strip():
            break
        next_request = resource_api.list_next(request, response)
        if next_request is None or next_request is request:
            break
        request = next_request
    return items


def _gcp_cloud_sql_instances(project_id: str) -> list[dict]:
    sqladmin = _seams()._discovery_client("sqladmin", "v1beta4")
    return _gcp_paginate_list(sqladmin.instances(), "items", project=project_id)


def _gcp_managed_zones(project_id: str) -> list[dict]:
    """Return every Cloud DNS managed zone in the project (all pages).

    A single ``managedZones.list`` page caps at 100 zones; reading only the
    first page silently drops later zones, so a non-DNSSEC / unlogged zone
    beyond page one would be a false PASS. Paginate to stay complete.
    """
    dns = _seams()._discovery_client("dns", "v1")
    return _gcp_paginate_list(dns.managedZones(), "managedZones", project=project_id)


def _gcp_bigquery_datasets(bq: Any, project_id: str) -> list[dict]:
    """Return every BigQuery dataset in the project (all pages).

    ``datasets.list`` is paginated; reading only the first page would let a
    publicly-accessible / unencrypted dataset on a later page pass unseen.
    """
    return _gcp_paginate_list(bq.datasets(), "datasets", projectId=project_id)


def _gcp_kms_crypto_keys(project_id: str) -> list[dict]:
    """Return every Cloud KMS crypto key in the project (all locations/key rings)."""
    kms = _seams()._discovery_client("cloudkms", "v1")
    keys: list[dict] = []
    locations = _gcp_paginate_list(kms.projects().locations(), "locations", name=f"projects/{project_id}")
    for loc in locations:
        loc_name = loc.get("name", "")
        if not loc_name:
            continue
        keyrings = _gcp_paginate_list(kms.projects().locations().keyRings(), "keyRings", parent=loc_name)
        for kr in keyrings:
            kr_name = kr.get("name", "")
            if not kr_name:
                continue
            keys.extend(_gcp_paginate_list(kms.projects().locations().keyRings().cryptoKeys(), "cryptoKeys", parent=kr_name))
    return keys


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class GCPCISReport:
    """Aggregated CIS GCP Foundation Benchmark results."""

    benchmark_version: str = "3.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    project_id: str = ""
    # Populated only by the multi-project fan-out: the projects actually
    # evaluated and any per-project warnings (e.g. a project skipped because the
    # credential could not read it). Empty for a single-project run.
    projects_scanned: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def errored(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.ERROR)

    @property
    def not_applicable(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NOT_APPLICABLE)

    @property
    def no_data(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.NO_DATA)

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.evaluated * 100) if self.evaluated else 0.0

    def to_dict(self) -> dict:
        from agent_bom.cloud.benchmark_manifests import benchmark_manifest
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "CIS Google Cloud Platform Foundation",
            "benchmark_version": self.benchmark_version,
            "benchmark_manifest": benchmark_manifest("gcp"),
            "project_id": self.project_id,
            "projects_scanned": self.projects_scanned,
            "warnings": self.warnings,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "not_applicable": self.not_applicable,
            "no_data": self.no_data,
            "evaluated": self.evaluated,
            "total": self.total,
            "checks": [
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status.value,
                    "severity": c.severity,
                    "evidence": c.evidence,
                    "resource_ids": c.resource_ids,
                    "recommendation": c.recommendation,
                    "remediation": c.remediation,
                    "cis_section": c.cis_section,
                    # Per-check project attribution for the multi-project fan-out;
                    # empty string on a single-project run.
                    "project_id": c.account_id,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Section labels
# ---------------------------------------------------------------------------

_IAM_SECTION = "1 - Identity and Access Management"
_LOGGING_SECTION = "2 - Logging"
_NETWORK_SECTION = "3 - Networking"
_COMPUTE_SECTION = "4 - Virtual Machines"
_STORAGE_SECTION = "5 - Cloud Storage"
_SQL_SECTION = "6 - Cloud SQL"
_BIGQUERY_SECTION = "7 - BigQuery"
