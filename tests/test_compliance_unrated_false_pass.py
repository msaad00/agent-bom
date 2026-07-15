"""A control with findings that are ALL unrated-severity must NOT read as PASS.

`_evaluated_control_status` (routes/compliance.py) and its mirror
`_control_status` (output/compliance_narrative.py) previously fell through to
``pass`` when a control HAS mapped findings but every finding is unrated
(sev_breakdown all-zero). That is a false pass: evidence exists but severity is
ungraded, so the control is ``not_evaluated`` — never a silent pass. A silent
pass inflated overall_score and contradicted the unrated-honesty principle.

These tests pin the fix across all three surfaces: the ``/v1/compliance`` API,
the narrative builder, and the shared status ladders — they must agree.
"""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.routes.compliance import _evaluated_control_status
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.output.compliance_narrative import _build_framework_narrative, _control_status
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _clear_jobs() -> None:
    from agent_bom.api.server import set_job_store

    set_job_store(InMemoryJobStore())


def _add_done_job(blast_radius: list[dict]) -> None:
    from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _get_store

    job = ScanJob(job_id="test-job", tenant_id="default", created_at="2026-02-22T10:00:00Z", request=ScanRequest())
    job.status = JobStatus.DONE
    job.completed_at = "2026-02-22T10:05:00Z"
    job.result = {"agents": [], "blast_radius": blast_radius, "threat_framework_summary": {}}
    _get_store().put(job)


# ─── Shared status ladders (both copies must agree) ──────────────────────────


def test_status_ladder_all_unrated_is_not_evaluated() -> None:
    all_unrated = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert _evaluated_control_status(all_unrated) == "not_evaluated"
    assert _control_status(all_unrated) == "not_evaluated"


def test_status_ladder_critical_or_high_is_fail() -> None:
    for sev in ("critical", "high"):
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, sev: 1}
        assert _evaluated_control_status(breakdown) == "fail"
        assert _control_status(breakdown) == "fail"


def test_status_ladder_medium_or_low_is_warning() -> None:
    for sev in ("medium", "low"):
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, sev: 1}
        assert _evaluated_control_status(breakdown) == "warning"
        assert _control_status(breakdown) == "warning"


# ─── /v1/compliance API ──────────────────────────────────────────────────────


def test_api_all_unrated_control_is_not_evaluated_not_pass() -> None:
    """A mapped finding with an unrated severity → control not_evaluated, and the
    overall_score is not inflated by that would-be pass."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-9999",
                "severity": "unknown",  # unrated → not in sev_breakdown
                "package": "leftpad",
                "affected_agents": ["claude-desktop"],
                "owasp_tags": ["LLM05"],
            }
        ]
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()

    llm05 = next(c for c in data["owasp_llm_top10"] if c["control_id"] == "LLM05")
    assert llm05["findings"] == 1
    assert llm05["status"] == "not_evaluated"  # NOT "pass"

    # No control passes (the only mapped one is unrated), so score is not inflated.
    assert data["summary"]["owasp_pass"] == 0
    assert data["summary"]["owasp_not_evaluated"] == 10
    assert data["overall_score"] == 0.0
    _clear_jobs()


def test_api_rated_finding_unchanged() -> None:
    """A rated (high) finding still fails — the fix only touches the all-unrated case."""
    _clear_jobs()
    _add_done_job(
        [
            {
                "vulnerability_id": "CVE-2025-1111",
                "severity": "high",
                "package": "express",
                "affected_agents": ["claude-desktop"],
                "owasp_tags": ["LLM05"],
            }
        ]
    )
    client = TestClient(app)
    data = client.get("/v1/compliance", headers=_AUTH_HEADERS).json()
    llm05 = next(c for c in data["owasp_llm_top10"] if c["control_id"] == "LLM05")
    assert llm05["status"] == "fail"
    assert data["summary"]["owasp_fail"] == 1
    _clear_jobs()


# ─── Narrative agreement ─────────────────────────────────────────────────────


def test_narrative_all_unrated_control_not_counted_as_pass() -> None:
    """The narrative must agree: an all-unrated control is not an evaluated pass,
    so the framework does not read as 'passing'."""
    blast = [
        {
            "vulnerability_id": "CVE-2025-9999",
            "severity": "unknown",
            "package": "leftpad",
            "affected_agents": ["claude-desktop"],
            "owasp_tags": ["LLM05"],
        }
    ]
    fw = _build_framework_narrative("owasp-llm", blast)
    # An all-unrated mapped control is not a pass → framework never 'passing',
    # and the score is not inflated by a silent pass.
    assert fw.status != "passing"
    assert fw.score == 0
