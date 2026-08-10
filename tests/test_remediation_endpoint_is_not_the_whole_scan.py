"""The remediation plan must be fetchable without downloading the whole scan.

The remediation page already had pagination, severity and framework filters, a
fixable-only toggle, sort and search. None of that was the reason it fell over
on the demo estate. It fetched the plan like this:

    getRemediation: async (jobId) => {
      const job = await get<ScanJob>(`/v1/scan/${jobId}`);
      return job.result?.remediation_plan ?? [];
    }

``GET /v1/scan/{job_id}`` returns the canonical AI-BOM document -- every
finding, every blast radius, every asset, every exposure path. Measured on the
demo estate (2,068 assets / 2,716 findings):

    whole job payload        8.7 MB
      blast_radius           4.5 MB
      findings               2.7 MB
      assets                 1.0 MB
      exposure_paths         1.0 MB
      remediation_plan      41.2 KB   <- the only field read

**99.5% of the transfer was discarded by the caller**, and the browser parsed
all of it before rendering 27 rows. The cost of the answer tracked the size of
the estate rather than the size of the plan -- the same shape as the roll-up
drill-down fix, one layer up.

So the endpoint serves the plan, and the guard is differential: the narrow read
must return exactly what the wide one carried, and must not carry the rest.
"""

from __future__ import annotations

import uuid

import pytest
from starlette.testclient import TestClient

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store

TENANT = "default"

# A plan item carries what the page renders: the upgrade, its blast-radius
# rollup, and the framework tags the chips are drawn from.
PLAN = [
    {
        "package": "langchain",
        "current_version": "0.0.150",
        "fixed_version": "0.1.0",
        "ecosystem": "PyPI",
        "severity": "critical",
        "impact_score": 9.4,
        "vulnerabilities": ["CVE-2025-0001", "CVE-2025-0002"],
        "affected_agents": ["cursor"],
        "exposed_credentials": ["AWS_SECRET_ACCESS_KEY"],
        "reachable_tools": ["run_shell"],
        "agents_pct": 100.0,
        "credentials_pct": 50.0,
        "tools_pct": 25.0,
        "owasp_tags": ["LLM05"],
        "atlas_tags": ["AML.T0010", "AML.T0012"],
        "is_kev": True,
        "risk_narrative": "Reachable from an agent with a live credential.",
    },
    {
        "package": "requests",
        "current_version": "2.20.0",
        "fixed_version": "",
        "ecosystem": "PyPI",
        "severity": "medium",
        "impact_score": 4.1,
        "vulnerabilities": ["CVE-2025-0003"],
        "affected_agents": [],
        "exposed_credentials": [],
        "reachable_tools": [],
        "agents_pct": 0.0,
        "credentials_pct": 0.0,
        "tools_pct": 0.0,
        "owasp_tags": [],
        "atlas_tags": [],
        "is_kev": False,
        "risk_narrative": "No fix published.",
    },
]

# The bulk the page never read. Sized so a payload carrying it is unmistakable.
BULK = {
    "findings": [{"id": f"CVE-2025-{i:04d}", "severity": "high", "blob": "x" * 512} for i in range(200)],
    "blast_radius": [{"vulnerability": {"id": f"CVE-2025-{i:04d}"}, "blob": "y" * 512} for i in range(200)],
    "assets": [{"asset_id": f"asset-{i}", "blob": "z" * 512} for i in range(200)],
}


@pytest.fixture
def client_and_job():
    store = InMemoryJobStore()
    job_id = str(uuid.uuid4())
    store.put(
        ScanJob(
            job_id=job_id,
            tenant_id=TENANT,
            status=JobStatus.DONE,
            created_at="2026-08-10T00:00:00Z",
            completed_at="2026-08-10T00:01:00Z",
            request=ScanRequest(agent_projects=["/tmp/proj"], offline=True),
            result={"remediation_plan": PLAN, **BULK},
        )
    )
    set_job_store(store)
    try:
        yield TestClient(app), job_id, store
    finally:
        set_job_store(InMemoryJobStore())


def test_the_plan_is_exactly_what_the_whole_job_carried(client_and_job):
    """Differential: a narrower read is only correct if the answer is identical."""
    client, job_id, _store = client_and_job
    wide = client.get(f"/v1/scan/{job_id}")
    narrow = client.get(f"/v1/scan/{job_id}/remediation")
    assert narrow.status_code == 200, narrow.text
    assert narrow.json()["remediation_plan"] == wide.json()["result"]["remediation_plan"]


def test_the_response_does_not_carry_the_rest_of_the_scan(client_and_job):
    """The point of the endpoint: what it leaves out."""
    client, job_id, _store = client_and_job
    payload = client.get(f"/v1/scan/{job_id}/remediation").json()
    for absent in ("findings", "blast_radius", "assets", "exposure_paths"):
        assert absent not in payload, f"{absent} came back on the remediation read"


def test_it_is_dramatically_smaller_than_the_whole_job(client_and_job):
    """Structural, not timing: the transfer must not track estate size."""
    client, job_id, _store = client_and_job
    wide = len(client.get(f"/v1/scan/{job_id}").content)
    narrow = len(client.get(f"/v1/scan/{job_id}/remediation").content)
    assert narrow * 10 < wide, f"narrow read {narrow}B is not materially smaller than {wide}B"


def test_it_reports_the_plan_size_so_a_client_never_infers_it(client_and_job):
    client, job_id, _store = client_and_job
    payload = client.get(f"/v1/scan/{job_id}/remediation").json()
    assert payload["total"] == len(PLAN)


def test_an_unfinished_scan_says_so_rather_than_returning_an_empty_plan(client_and_job):
    """An empty plan and a scan that has not produced one are different answers."""
    client, _job_id, store = client_and_job
    pending = str(uuid.uuid4())
    store.put(
        ScanJob(
            job_id=pending,
            tenant_id=TENANT,
            status=JobStatus.RUNNING,
            created_at="2026-08-10T00:00:00Z",
            request=ScanRequest(agent_projects=["/tmp/proj"], offline=True),
        )
    )
    response = client.get(f"/v1/scan/{pending}/remediation")
    assert response.status_code == 409, response.text


def test_a_completed_scan_with_no_plan_returns_an_empty_one(client_and_job):
    client, _job_id, store = client_and_job
    empty = str(uuid.uuid4())
    store.put(
        ScanJob(
            job_id=empty,
            tenant_id=TENANT,
            status=JobStatus.DONE,
            created_at="2026-08-10T00:00:00Z",
            completed_at="2026-08-10T00:01:00Z",
            request=ScanRequest(agent_projects=["/tmp/proj"], offline=True),
            result={"findings": []},
        )
    )
    payload = client.get(f"/v1/scan/{empty}/remediation").json()
    assert payload["remediation_plan"] == []
    assert payload["total"] == 0


def test_an_unknown_job_is_not_found(client_and_job):
    client, _job_id, store = client_and_job
    assert client.get(f"/v1/scan/{uuid.uuid4()}/remediation").status_code == 404
