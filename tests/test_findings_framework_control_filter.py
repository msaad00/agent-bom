"""Compliance drill-through filter on GET /v1/findings (epic #4790, ws 3a).

The Compliance view links a control's non-zero finding count to
``/findings?framework=<section id>&control=<code>``. Until now neither the API
nor the UI honoured those params, so the link landed on an UNFILTERED queue. The
per-control count on the badge is derived from the scan ``blast_radius`` entries
via ``br.get(tag_field)`` (``code in tags``), so the drilled queue has to filter
on the SAME per-framework control tags to reconcile with the number the user
clicked.

The predicate lives in ``row_matches_scope`` — the single source of truth shared
by the route's in-memory scan findings and the hub store's bulk-ingested rows —
so the two paths cannot diverge. The framework identifier is resolved once, in
the route, to the finding's ``*_tags`` field and canonical slug.
"""

from __future__ import annotations

from datetime import datetime, timezone

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.models import JobStatus
from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_store
from agent_bom.compliance_coverage import resolve_framework_filter
from agent_bom.finding_scope import row_matches_scope
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


# ── Resolver: UI section id → finding tag field ──────────────────────────────


def test_resolver_maps_every_ui_section_id() -> None:
    """The compliance page's section ids must all resolve to a tag field.

    Two ids do not equal the metadata slug (``nist-ai-rmf`` → ``nist``,
    ``iso27001`` → ``iso-27001``); the resolver strips separators so both land.
    """
    cases = {
        "owasp-llm": "owasp_tags",
        "owasp-mcp": "owasp_mcp_tags",
        "atlas": "atlas_tags",
        "nist-ai-rmf": "nist_ai_rmf_tags",
        "owasp-agentic": "owasp_agentic_tags",
        "eu-ai-act": "eu_ai_act_tags",
        "nist-csf": "nist_csf_tags",
        "iso27001": "iso_27001_tags",
        "soc2": "soc2_tags",
        "cis": "cis_tags",
        "cmmc": "cmmc_tags",
        "nist-800-53": "nist_800_53_tags",
        "pci-dss": "pci_dss_tags",
        "fedramp": "fedramp_tags",
    }
    for section_id, tag_field in cases.items():
        meta = resolve_framework_filter(section_id)
        assert meta is not None, section_id
        assert meta.tag_field == tag_field, section_id


def test_resolver_returns_none_for_unknown_framework() -> None:
    assert resolve_framework_filter("not-a-framework") is None
    assert resolve_framework_filter("") is None


# ── Predicate: row_matches_scope with pre-resolved filters ───────────────────


def _row(**overrides: object) -> dict:
    base: dict = {"id": "f", "severity": "high", "title": "t"}
    base.update(overrides)
    return base


def test_control_filter_is_exact_containment_in_the_tag_field() -> None:
    filters = {"framework_tag_field": "soc2_tags", "framework_slug": "soc2", "control": "CC6.1"}
    assert row_matches_scope(_row(soc2_tags=["CC6.1", "CC7.2"]), filters) is True
    assert row_matches_scope(_row(soc2_tags=["CC7.2"]), filters) is False
    assert row_matches_scope(_row(), filters) is False


def test_control_matching_never_crosses_frameworks() -> None:
    """A CIS code must not match a SOC 2 drill even via the flattened tags."""
    filters = {"framework_tag_field": "soc2_tags", "framework_slug": "soc2", "control": "4.1"}
    row = _row(cis_tags=["4.1"], framework_tags=["cis:4.1"], applicable_frameworks=["cis", "soc2"])
    assert row_matches_scope(row, filters) is False


def test_framework_only_matches_any_control_or_the_slug() -> None:
    resolved = {"framework_tag_field": "cis_tags", "framework_slug": "cis"}
    # A row carrying a CIS control tag matches.
    assert row_matches_scope(_row(cis_tags=["4.1"]), resolved) is True
    # A bulk-ingested row whose per-framework tags were redacted at rest still
    # matches on the retained applicable_frameworks slug.
    assert row_matches_scope(_row(applicable_frameworks=["cis"]), resolved) is True
    # A row for a different framework does not.
    assert row_matches_scope(_row(soc2_tags=["CC6.1"], applicable_frameworks=["soc2"]), resolved) is False


def test_unresolved_framework_filter_matches_nothing() -> None:
    """An unknown framework returns an honest empty match, never everything."""
    assert row_matches_scope(_row(soc2_tags=["CC6.1"]), {"framework": "bogus"}) is False


def test_framework_control_composes_with_other_scope_filters() -> None:
    filters = {"framework_tag_field": "soc2_tags", "framework_slug": "soc2", "control": "CC6.1", "provider": "aws"}
    row = _row(soc2_tags=["CC6.1"], provider="aws")
    assert row_matches_scope(row, filters) is True
    assert row_matches_scope(_row(soc2_tags=["CC6.1"], provider="gcp"), filters) is False


# ── Route: GET /v1/findings?framework=&control= ──────────────────────────────


def _seed() -> None:
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    observed_at = datetime.now(timezone.utc).isoformat()
    job = ScanJob(job_id="fw-job", tenant_id="default", created_at=observed_at, request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = observed_at
    job.result = {
        "agents": [],
        "scan_sources": ["cloud"],
        "findings": [
            {
                "id": "f-soc2-cis",
                "severity": "high",
                "title": "soc2 CC6.1 + cis 4.1",
                "soc2_tags": ["CC6.1"],
                "cis_tags": ["4.1"],
                "applicable_frameworks": ["soc2", "cis"],
            },
            {
                "id": "f-soc2-only",
                "severity": "medium",
                "title": "soc2 CC7.2",
                "soc2_tags": ["CC7.2"],
                "applicable_frameworks": ["soc2"],
            },
            {
                "id": "f-nistcsf",
                "severity": "critical",
                "title": "nist csf PR.AC-1",
                "nist_csf_tags": ["PR.AC-1"],
                "applicable_frameworks": ["nist-csf"],
            },
            {
                "id": "f-cis-slug-only",
                "severity": "low",
                "title": "cis by slug, tags redacted",
                "applicable_frameworks": ["cis"],
            },
        ],
    }
    _get_store().put(job)


def _ids(resp) -> set[str]:
    return {f.get("id") for f in resp.json()["findings"]}


def test_route_framework_filter_narrows_to_that_framework() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?framework=soc2", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-soc2-cis", "f-soc2-only"}


def test_route_control_filter_narrows_within_framework() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?framework=soc2&control=CC6.1", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-soc2-cis"}


def test_route_control_reconciles_with_the_drill_link() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?framework=soc2&control=CC7.2", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-soc2-only"}


def test_route_framework_includes_slug_only_rows_but_control_does_not() -> None:
    _seed()
    fw = TestClient(app).get("/v1/findings?framework=cis", headers=_AUTH)
    assert _ids(fw) == {"f-soc2-cis", "f-cis-slug-only"}
    ctrl = TestClient(app).get("/v1/findings?framework=cis&control=4.1", headers=_AUTH)
    assert _ids(ctrl) == {"f-soc2-cis"}


def test_route_hyphenated_ui_slug_resolves() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?framework=nist-csf&control=PR.AC-1", headers=_AUTH)
    assert resp.status_code == 200
    assert _ids(resp) == {"f-nistcsf"}


def test_route_unknown_framework_returns_empty_not_everything() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?framework=not-a-framework", headers=_AUTH)
    assert resp.status_code == 200
    assert resp.json()["findings"] == []


def test_route_echoes_framework_and_control_filters() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings?framework=soc2&control=CC6.1", headers=_AUTH)
    assert resp.json()["filters"] == {"framework": "soc2", "control": "CC6.1"}


def test_route_no_framework_filter_is_backward_compatible() -> None:
    _seed()
    resp = TestClient(app).get("/v1/findings", headers=_AUTH)
    assert resp.status_code == 200
    assert len(resp.json()["findings"]) == 4
