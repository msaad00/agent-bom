"""Differential correctness for the facet severity pushdown.

The optimised path must be indistinguishable from the walk it replaces. Each
case runs the same request twice against the same seeded store — once with the
store aggregate available, once with it disabled so the legacy unfiltered walk
runs — and asserts the two envelopes agree on the facets, the total, the
completeness metadata and the returned rows.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "tenant-facet-diff"
SEVERITIES = ("critical", "high", "medium", "low", "info", "informational")
PROVIDERS = ("aws", "azure", "gcp")
ENVIRONMENTS = ("prod", "staging")
PACKAGES = ("requests", "log4j-core", "lodash")
FINDING_TYPES = ("CVE", "SAST", "CREDENTIAL_EXPOSURE", "MISCONFIGURATION")


@pytest.fixture(autouse=True)
def _stores() -> Any:
    enable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    yield
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    disable_trusted_proxy_env()


def _seed(count: int = 240) -> None:
    store = InMemoryComplianceHubStore()
    rows = []
    for index in range(count):
        finding_type = FINDING_TYPES[index % len(FINDING_TYPES)]
        rows.append(
            {
                "id": f"diff-{index}",
                "canonical_id": f"diff-{index}",
                "finding_type": finding_type,
                "source": "SBOM" if finding_type == "CVE" else finding_type,
                "cve_id": f"CVE-2026-{2000 + index}" if finding_type == "CVE" else None,
                "title": f"{PACKAGES[index % len(PACKAGES)]} issue {index}",
                "package": PACKAGES[index % len(PACKAGES)],
                "severity": SEVERITIES[index % len(SEVERITIES)],
                "provider": PROVIDERS[index % len(PROVIDERS)],
                "account_ref": f"acct-{index % 4}",
                "environment": ENVIRONMENTS[index % len(ENVIRONMENTS)],
                "origin": "bulk_ingest",
                "batch_id": "diff-batch",
            }
        )
    store.add(TENANT, rows)
    store.upsert_current_batch(
        TENANT,
        rows,
        observed_at="2026-07-30T00:00:00Z",
        batch_id="diff-batch",
        source="fixture",
    )
    set_compliance_hub_store(store)


CASES = [
    {"include_facets": "true", "window_days": 0},
    {"include_facets": "true", "window_days": 0, "severity": "critical"},
    {"include_facets": "true", "window_days": 0, "severity": "high"},
    {"include_facets": "true", "window_days": 0, "severity": "info"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "status": "all"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "status": "open"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "sort": "cvss"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "sort": "severity"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "limit": 5},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "limit": 5, "offset": 10},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "provider": "aws"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "environment": "prod"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "domain": "vuln"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "finding_class": "vulnerability"},
    {"include_facets": "true", "window_days": 0, "severity": "critical", "q": "log4j-core"},
    {"include_facets": "true", "window_days": 0, "severity": "medium", "provider": "azure", "limit": 3},
]


@pytest.mark.parametrize("params", CASES, ids=lambda case: "&".join(f"{k}={v}" for k, v in sorted(case.items())))
def test_pushdown_matches_the_unfiltered_walk(params: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _seed()
    client = TestClient(app)
    headers = proxy_headers(tenant=TENANT, role="analyst")

    optimised = client.get("/v1/findings", params=params, headers=headers)
    assert optimised.status_code == 200, optimised.text

    # Disable the aggregate so the legacy unfiltered Python walk runs instead.
    monkeypatch.setattr(
        "agent_bom.api.routes.scan._facet_severity_histogram",
        lambda *_args, **_kwargs: None,
    )
    legacy = client.get("/v1/findings", params=params, headers=headers)
    assert legacy.status_code == 200, legacy.text

    new_body = optimised.json()
    old_body = legacy.json()

    assert new_body["facets"] == old_body["facets"], "facet counts diverged from the walk"
    assert new_body["total"] == old_body["total"]
    assert new_body["facets_approximate"] == old_body["facets_approximate"]
    assert [row["id"] for row in new_body["findings"]] == [row["id"] for row in old_body["findings"]]
    assert new_body["findings"] == old_body["findings"]

    # ``scanned_rows`` is the one field that is *meant* to move: it reports how
    # many rows the walk had to visit, and cutting that is the whole point. The
    # honesty-bearing fields must not move with it.
    new_completeness = dict(new_body["facet_metadata"]["completeness"])
    old_completeness = dict(old_body["facet_metadata"]["completeness"])
    new_scanned = new_completeness.pop("scanned_rows")
    old_scanned = old_completeness.pop("scanned_rows")
    assert new_completeness == old_completeness, "completeness honesty signal diverged"
    assert new_scanned <= old_scanned, "pushdown made the walk visit more rows, not fewer"


def test_pushdown_is_actually_exercised_by_the_differential_cases() -> None:
    """Guard the guard: at least one case must take the optimised path.

    Without this, disabling the aggregate everywhere would make the differential
    suite vacuously green.
    """
    from agent_bom.api.routes.scan import _facet_severity_histogram

    _seed()
    taken = _facet_severity_histogram(
        TENANT,
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="open",
    )
    assert taken is not None, "no differential case exercises the pushdown"
    assert sum(taken.values()) > 0

    # And the documented bail-outs really do fall back to the walk.
    for scope in ({"provider": "aws"}, {"q": "log4j"}, {"domain": "vuln"}):
        assert (
            _facet_severity_histogram(
                TENANT, severity="critical", scan_id=None, since=None, scope=scope, status="open"
            )
            is None
        )
    assert (
        _facet_severity_histogram(
            TENANT, severity=None, scan_id=None, since=None, scope={}, status="open"
        )
        is None
    )
