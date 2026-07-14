"""Tests for the cross-domain /v1/overview aggregation endpoint."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import JobStatus, _get_store, app, configure_api
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")
_ADMIN_HEADERS = proxy_headers(role="admin", tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _clear_jobs() -> None:
    from agent_bom.api.server import set_job_store

    set_job_store(InMemoryJobStore())


def _add_done_job(
    blast_radius: list[dict],
    job_id: str = "test-job",
    *,
    tenant_id: str = "default",
    result_extra: dict | None = None,
) -> None:
    from agent_bom.api.server import ScanJob, ScanRequest

    job = ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "agents": [],
        "blast_radius": blast_radius,
        "scan_sources": ["agent_discovery"],
    }
    if result_extra:
        job.result.update(result_extra)
    _get_store().put(job)


_EXPECTED_DOMAINS = {"cloud", "vuln", "code", "runtime", "cost", "identity", "ops"}


def test_overview_empty_shape() -> None:
    """With no scans the endpoint returns the full domain skeleton at zero."""
    _clear_jobs()
    client = TestClient(app)
    resp = client.get("/v1/overview", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["schema_version"] == "overview.v1"
    assert data["tenant_id"] == "default"
    assert set(data["domains"].keys()) == _EXPECTED_DOMAINS
    assert data["headline"]["critical"] == 0
    assert data["headline"]["scans"] == 0
    assert data["top_risks"] == []
    assert data["posture"]["grade"] == "N/A"

    for domain in data["domains"].values():
        assert {"label", "href", "metric", "metric_label", "status", "detail"} <= set(domain)
        assert domain["href"].startswith("/")
        if "graph_href" in domain:
            assert str(domain["graph_href"]).startswith("/graph")


def test_overview_aggregates_findings() -> None:
    """A completed scan with findings populates severity, top risks, and ops."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-0001",
                "package": "demo",
                "severity": "critical",
                "risk_score": 9.5,
                "cisa_kev": True,
                "exposed_credentials": ["DEMO_TOKEN"],
            },
            {
                "vulnerability_id": "CVE-2025-0002",
                "package": "demo2",
                "severity": "high",
                "blast_score": 70,
            },
        ]
    )
    client = TestClient(app)
    resp = client.get("/v1/overview", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    assert data["headline"]["critical"] == 1
    assert data["headline"]["high"] == 1
    assert data["headline"]["critical_high"] == 2
    assert data["headline"]["kev"] == 1
    assert data["headline"]["credential_exposed"] == 1
    assert data["headline"]["scans"] == 1

    cloud = data["domains"]["cloud"]
    assert cloud["metric_label"] == "accounts connected"
    assert cloud["status"] in {"ok", "idle"}

    vuln = data["domains"]["vuln"]
    assert vuln["metric"] == 2  # two unique CVEs
    assert vuln["status"] == "critical"
    assert vuln["detail"]["kev"] == 1

    ops = data["domains"]["ops"]
    assert ops["metric"] == 1  # one completed scan
    assert ops["detail"]["done"] == 1

    assert data["top_risks"][0]["vulnerability_id"] == "CVE-2025-0001"
    assert data["top_risks"][0]["risk_score"] == 9.5
    assert len(data["top_risks"]) == 2


def test_overview_reads_compacted_scan_summary() -> None:
    """Hot-cache compaction must not zero out posture/CVE tiles on /v1/overview."""
    from agent_bom.api.server import ScanJob, ScanRequest
    from agent_bom.api.stores import _compact_terminal_job

    _clear_jobs()
    job = ScanJob(
        job_id="compact-job",
        tenant_id="default",
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "summary": {
            "total_vulnerabilities": 87,
            "critical_unified_findings": 3,
            "high_unified_findings": 12,
            "unique_packages": 9,
        },
        "posture_scorecard": {
            "grade": "F",
            "score": 42.0,
            "summary": "Poor posture",
            "dimensions": {},
        },
        "scan_sources": ["agent_discovery"],
        "blast_radius": [
            {
                "vulnerability_id": "CVE-IGNORED",
                "severity": "critical",
                "risk_score": 10,
            }
        ],
    }
    _get_store().put(_compact_terminal_job(job))

    client = TestClient(app)
    resp = client.get("/v1/overview", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()

    # The configurable exec-score engine (#3940) recomputes the grade from the
    # honest estate counts and takes the *worst* of that and the scan scorecard
    # floor (42.0). 3 critical + 12 high + 72 unrated is heavy pressure, so the
    # diminishing-returns score lands well below the floor — still an F, and the
    # CVE/severity tiles are populated (the compaction-must-not-zero-tiles intent
    # this test guards).
    assert data["posture"]["grade"] == "F"
    assert data["posture"]["score"] <= 42.0
    assert data["headline"]["critical"] == 3
    assert data["headline"]["high"] == 12
    assert data["domains"]["vuln"]["metric"] == 87


def _ingest_hub_findings(findings: list[dict], *, tenant_id: str = "default") -> None:
    """Append normalized findings straight into the compliance-hub ledger.

    Mirrors what POST /v1/findings/bulk persists (hub_store.add) so the overview
    can be exercised against ingested evidence without a full HTTP round-trip.
    """
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    get_compliance_hub_store().add(tenant_id, findings)


def test_overview_counts_bulk_ingested_findings() -> None:
    """Findings ingested via the hub (POST /v1/findings/bulk) move headline + grade."""
    _clear_jobs()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    get_compliance_hub_store().clear("default")

    client = TestClient(app)
    # Baseline: no scans, no ingest -> N/A posture, zero headline.
    baseline = client.get("/v1/overview", headers=_AUTH_HEADERS).json()
    assert baseline["posture"]["grade"] == "N/A"
    assert baseline["headline"]["critical"] == 0
    assert baseline["headline"]["hub_findings"] == 0

    _ingest_hub_findings(
        [
            {"finding_id": "F-1", "severity": "critical", "title": "boom"},
            {"finding_id": "F-2", "severity": "critical", "title": "boom2"},
            {"finding_id": "F-3", "severity": "high", "title": "warn"},
        ]
    )

    data = client.get("/v1/overview", headers=_AUTH_HEADERS).json()
    assert data["headline"]["critical"] == 2
    assert data["headline"]["high"] == 1
    assert data["headline"]["critical_high"] == 3
    assert data["headline"]["hub_findings"] == 3
    # Two criticals + one high drive the grade off N/A and down to a failing band.
    assert data["posture"]["grade"] not in {"N/A", "A"}
    assert data["posture"]["score"] < 100.0

    get_compliance_hub_store().clear("default")


def test_overview_hub_findings_do_not_upgrade_failing_scan() -> None:
    """Ingested evidence can only move a scan grade down, never launder it up."""
    _clear_jobs()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    get_compliance_hub_store().clear("default")
    _add_done_job(
        [{"vulnerability_id": "CVE-2025-9999", "severity": "critical", "risk_score": 10}],
        result_extra={
            "posture_scorecard": {"grade": "F", "score": 30.0, "summary": "Failing"},
        },
    )
    _ingest_hub_findings([{"finding_id": "H-1", "severity": "low", "title": "minor"}])

    data = client_get_overview()
    # Low-severity ingest must not raise the F grade / 30.0 score.
    assert data["posture"]["grade"] == "F"
    assert data["posture"]["score"] <= 30.0
    assert data["headline"]["hub_findings"] == 1

    get_compliance_hub_store().clear("default")


def client_get_overview() -> dict:
    return TestClient(app).get("/v1/overview", headers=_AUTH_HEADERS).json()


def test_overview_severity_sum_equals_unique_cves_with_unknown_severity() -> None:
    """The 39-CVEs / 0-severities bug: unknown-severity findings must not vanish.

    A finding with a severity the histogram doesn't recognize lands in the
    ``unrated`` bucket, and ``sum(severity.values()) == unique_cves`` holds.
    """
    _clear_jobs()
    _add_done_job(
        [
            {"vulnerability_id": "CVE-A", "severity": "critical", "risk_score": 9},
            {"vulnerability_id": "CVE-B", "severity": "unknown", "risk_score": 5},
            {"vulnerability_id": "CVE-C", "severity": "", "risk_score": 4},
        ]
    )
    data = client_get_overview()
    vuln = data["domains"]["vuln"]
    strip = vuln["detail"]["severity"]
    assert strip["critical"] == 1
    assert strip["unrated"] == 2
    assert sum(strip.values()) == vuln["metric"]
    assert vuln["metric"] == 3


def test_overview_coverage_lanes_map_to_five_domains() -> None:
    """Coverage lanes are the five security domains, non-overlapping, invariant-clean."""
    _clear_jobs()
    from agent_bom.api.server import ScanJob, ScanRequest

    job = ScanJob(
        job_id="dom-job",
        tenant_id="default",
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "agents": [],
        "scan_sources": ["cloud"],
        "findings": [
            {"security_domain": "cspm", "severity": "high", "id": "c1"},
            {"security_domain": "cspm", "severity": "unknown", "id": "c2"},
            {"security_domain": "vuln", "severity": "critical", "id": "v1"},
            {"security_domain": "aispm", "severity": "medium", "id": "a1"},
        ],
    }
    _get_store().put(job)

    data = client_get_overview()
    coverage = {lane["domain"]: lane for lane in data["coverage"]}
    assert set(coverage) == {"cspm", "vuln", "appsec_sca", "dspm", "aispm"}

    cspm = coverage["cspm"]
    assert cspm["count"] == 2
    assert cspm["severity"]["high"] == 1
    assert cspm["severity"]["unrated"] == 1
    assert sum(cspm["severity"].values()) == cspm["count"]

    assert coverage["vuln"]["count"] == 1
    assert coverage["aispm"]["count"] == 1
    assert coverage["dspm"]["count"] == 0
    assert coverage["appsec_sca"]["count"] == 0
    # CIS misconfig went to CSPM, not the vuln lane.
    assert coverage["vuln"]["severity"]["critical"] == 1


def test_overview_headline_reflects_noncve_spine_critical() -> None:
    """A scan-produced non-CVE critical (malicious pkg) reaches headline + grade.

    Regression for the exec-read divergence (#3961): the headline + grade read
    the CVE-only ``blast_radius`` while the coverage lanes read the unified
    ``findings`` spine. A malicious/blocklisted-package critical present in the
    spine (and /v1/findings) but absent from blast_radius was invisible in the
    headline critical/high and the grade. They must now agree.
    """
    _clear_jobs()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.server import ScanJob, ScanRequest

    get_compliance_hub_store().clear("default")
    job = ScanJob(
        job_id="spine-job",
        tenant_id="default",
        created_at="2026-02-22T10:00:00Z",
        request=ScanRequest(),
    )
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {
        "agents": [],
        "scan_sources": ["agent_discovery"],
        # blast_radius carries only a lower-severity CVE — the old CVE-only basis.
        "blast_radius": [
            {"vulnerability_id": "CVE-2025-1000", "package": "libcve", "severity": "medium", "risk_score": 4},
        ],
        # The unified spine additionally carries a malicious-package CRITICAL that
        # never becomes a blast_radius row (a non-CVE finding the pipeline adds).
        "findings": [
            {"id": "vuln-cve", "security_domain": "vuln", "severity": "medium", "cve_id": "CVE-2025-1000"},
            {
                "id": "mal-1",
                "security_domain": "appsec_sca",
                "severity": "critical",
                "is_malicious": True,
                "title": "malicious package foo",
            },
        ],
    }
    _get_store().put(job)

    data = client_get_overview()
    # The critical from the spine now reaches the headline (was invisible before).
    assert data["headline"]["critical"] == 1
    # Coverage (which always read the spine) and the headline now agree.
    coverage = {lane["domain"]: lane for lane in data["coverage"]}
    assert coverage["appsec_sca"]["severity"]["critical"] == 1
    # The grade moves off a clean posture — a critical carries penalty.
    assert data["posture"]["grade"] not in {"N/A", "A"}
    crit_row = next(r for r in data["posture"]["breakdown"] if r["driver"] == "critical")
    assert crit_row["count"] == 1
    get_compliance_hub_store().clear("default")


def test_overview_compliance_failing_moves_grade() -> None:
    """A failing compliance framework feeds the exec grade (was hardcoded 0) (#3962)."""
    _clear_jobs()
    _reset_score_config()
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store
    from agent_bom.api.server import ScanJob, ScanRequest

    get_compliance_hub_store().clear("default")

    def _put_job(frameworks: list[str]) -> None:
        job = ScanJob(
            job_id="cmp-job",
            tenant_id="default",
            created_at="2026-02-22T10:00:00Z",
            request=ScanRequest(),
        )
        job.status = JobStatus.DONE
        job.completed_at = "2026-02-22T10:05:00Z"
        job.result = {
            "agents": [],
            "scan_sources": ["cloud"],
            "findings": [
                {"id": "f-crit", "security_domain": "cspm", "severity": "critical", "applicable_frameworks": frameworks},
            ],
        }
        _get_store().put(job)

    # Baseline: identical critical, no framework mapping — compliance driver == 0.
    _put_job([])
    base = client_get_overview()
    base_cmp = next(r for r in base["posture"]["breakdown"] if r["driver"] == "compliance")
    assert base_cmp["count"] == 0

    # Same critical, now mapped to two failing frameworks — the grade drops further.
    _clear_jobs()
    _put_job(["soc2", "iso_27001"])
    failing = client_get_overview()
    cmp_row = next(r for r in failing["posture"]["breakdown"] if r["driver"] == "compliance")
    assert cmp_row["count"] >= 1
    assert cmp_row["contribution"] > 0
    # The added compliance penalty pushes the score strictly below the no-framework case.
    assert failing["posture"]["score"] < base["posture"]["score"]
    _reset_score_config()
    get_compliance_hub_store().clear("default")


def test_overview_sheds_with_429_when_backpressure_opens(monkeypatch) -> None:
    """/v1/overview offloads store work off the event loop and sheds under overload (#3963)."""
    import time

    from agent_bom.api.routes import overview as overview_routes
    from agent_bom.backpressure import reset_backpressure_for_tests

    _clear_jobs()
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_OVERVIEW_P99_MS", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_OVERVIEW_MIN_SAMPLES", "1")
    monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_OVERVIEW_COOLDOWN_SECONDS", "30")
    reset_backpressure_for_tests()

    original = overview_routes._build_overview

    def _slow(*args, **kwargs):
        time.sleep(0.01)
        return original(*args, **kwargs)

    monkeypatch.setattr(overview_routes, "_build_overview", _slow)
    client = TestClient(app)
    try:
        warm = client.get("/v1/overview", headers=_AUTH_HEADERS)
        assert warm.status_code == 200
        shed = client.get("/v1/overview", headers=_AUTH_HEADERS)
        assert shed.status_code == 429
        body = shed.json()["detail"]
        assert body["path"] == "overview"
        assert int(shed.headers["Retry-After"]) >= 1
    finally:
        reset_backpressure_for_tests()


def test_overview_posture_blurb_not_no_vulns_when_counted() -> None:
    """Posture summary must never claim no vulnerabilities when the count > 0."""
    _clear_jobs()
    _add_done_job(
        [{"vulnerability_id": "CVE-X", "severity": "high", "risk_score": 7}],
    )
    data = client_get_overview()
    blurb = str(data["posture"]["summary"]).lower()
    assert "no vulnerabilit" not in blurb


def test_overview_requires_auth(monkeypatch) -> None:
    """Endpoint is read-only but still behind the standard viewer gate."""
    _clear_jobs()
    # The shared harness enables the anonymous opt-in by default; this contract
    # asserts fail-closed auth, so disable it and rebuild the middleware.
    monkeypatch.delenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", raising=False)
    configure_api(api_key=None)
    client = TestClient(app)
    resp = client.get("/v1/overview")
    assert resp.status_code in (401, 403)


def _reset_score_config() -> None:
    from agent_bom.api.stores import set_tenant_score_config_store
    from agent_bom.api.tenant_score_config_store import InMemoryTenantScoreConfigStore

    set_tenant_score_config_store(InMemoryTenantScoreConfigStore())


def test_score_config_defaults_and_update_roundtrip() -> None:
    """GET returns the documented default model; PUT persists a canonical override."""
    _reset_score_config()
    client = TestClient(app)

    default = client.get("/v1/overview/score-config", headers=_AUTH_HEADERS).json()
    assert default["active_override"] is False
    assert default["display_format"] == "percent"
    assert default["weights"]["critical"] == 12.0
    assert any(d["driver"] == "kev" for d in default["drivers"])

    resp = client.put(
        "/v1/overview/score-config",
        headers=_ADMIN_HEADERS,
        json={"display_format": "grade", "weights": {"critical": 20}},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["active_override"] is True
    assert updated["display_format"] == "grade"
    assert updated["weights"]["critical"] == 20.0

    # Persisted: a fresh GET reflects the override and the overview grade uses it.
    again = client.get("/v1/overview/score-config", headers=_AUTH_HEADERS).json()
    assert again["weights"]["critical"] == 20.0
    _reset_score_config()


def test_score_config_update_never_raises_on_garbage() -> None:
    """Out-of-range / junk overrides are clamped server-side, never 422/500."""
    _reset_score_config()
    client = TestClient(app)
    resp = client.put(
        "/v1/overview/score-config",
        headers=_ADMIN_HEADERS,
        json={"weights": {"critical": -999, "bogus": 5}, "display_format": "nonsense", "grade_thresholds": {"A": 40, "B": 90}},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["weights"]["critical"] == 0.0  # negative clamped
    assert "bogus" not in data["weights"]
    assert data["display_format"] == "percent"  # invalid -> default
    # Thresholds kept monotonic A>=B despite inverted input.
    assert data["grade_thresholds"]["A"] >= data["grade_thresholds"]["B"]
    _reset_score_config()


def test_overview_posture_carries_score_breakdown() -> None:
    """The overview posture exposes the weighted-input breakdown for explainability."""
    _clear_jobs()
    _reset_score_config()
    _add_done_job([{"vulnerability_id": "CVE-1", "severity": "critical", "risk_score": 9}])
    data = client_get_overview()
    posture = data["posture"]
    assert posture["grade"] in {"A", "B", "C", "D", "F"}
    assert "breakdown" in posture and isinstance(posture["breakdown"], list)
    crit_row = next(row for row in posture["breakdown"] if row["driver"] == "critical")
    assert crit_row["count"] == 1
    assert crit_row["contribution"] == crit_row["weight"] * 1
    assert posture["display_format"] == "percent"
    _reset_score_config()


def test_score_config_update_requires_admin() -> None:
    """A viewer token cannot mutate the tenant score model (admin-gated verb)."""
    _reset_score_config()
    viewer_headers = proxy_headers(tenant="default", role="viewer")
    client = TestClient(app)
    resp = client.put("/v1/overview/score-config", headers=viewer_headers, json={"display_format": "grade"})
    assert resp.status_code in (401, 403)
    _reset_score_config()


def test_overview_is_read_only() -> None:
    """No mutating verb reaches a handler.

    Only GET is registered, and the viewer role used by the overview page is
    denied mutating methods by the RBAC middleware (403) before any 405 from
    the router — either status confirms there is no write path here.
    """
    _clear_jobs()
    client = TestClient(app)
    assert client.post("/v1/overview", headers=_AUTH_HEADERS).status_code in (403, 405)
    assert client.delete("/v1/overview", headers=_AUTH_HEADERS).status_code in (403, 405)
