import json

import pytest

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.pipeline import _now, _run_scan_sync
from agent_bom.api.stores import _COMPACTED_RESULT_MARKER
from agent_bom.mcp_tools.scanning import scan_impl

_CONTRACT_KEYS = ("agents", "blast_radii", "blast_radius", "status", "vulnerabilities", "warnings")


class _RetainingStore:
    """Job store that shares the caller's job object, like ``InMemoryJobStore``.

    The pipeline's ``finally`` block compacts terminal results *in place* when
    the active store declares ``retains_job_objects_in_memory = False`` (the
    durable SQLite/Postgres/Snowflake stores). That compaction strips
    ``agents``/``status``/``blast_radius``/... off the very object a synchronous
    caller is holding, replacing them with a hot-cache stub.

    The global job store is a process-wide singleton, so if an earlier test in
    the suite left a durable store installed via ``set_job_store`` without
    restoring it, this contract test would inherit it and see a compacted
    ``job.result`` (``agents == None``) instead of the canonical empty shape
    (``agents == []``) — the CI flake this guards against. Pinning a retaining
    store makes the HTTP surface's response shape deterministic regardless of
    test ordering.
    """

    retains_job_objects_in_memory = True

    def __init__(self) -> None:
        self.jobs: list[ScanJob] = []

    def put(self, job: ScanJob) -> None:
        self.jobs.append(job)


def _truncate(value: str) -> str:
    return value


async def _empty_scan_pipeline(*_args, **_kwargs):
    return [], [], [], []


def _contract_subset(payload: dict[str, object]) -> dict[str, object]:
    return {key: payload.get(key) for key in _CONTRACT_KEYS}


@pytest.mark.asyncio
async def test_mcp_scan_no_agent_shape_matches_http_scan(monkeypatch):
    """Guard the shared scan response contract across MCP and HTTP surfaces."""
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda **_kwargs: [])
    # Isolate from the process-global job store singleton so a durable store
    # leaked by an earlier test cannot compaction-strip ``job.result`` (see
    # _RetainingStore) and flip the HTTP surface's empty-scan shape.
    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: _RetainingStore())

    job = ScanJob(
        job_id="contract-no-agents",
        created_at=_now(),
        request=ScanRequest(),
    )
    _run_scan_sync(job)
    assert job.result is not None

    raw_mcp = await scan_impl(
        _run_scan_pipeline=_empty_scan_pipeline,
        _truncate_response=_truncate,
    )
    mcp_result = json.loads(raw_mcp)

    # Neither surface may hand back a compacted hot-cache stub for a live scan.
    assert _COMPACTED_RESULT_MARKER not in mcp_result
    assert _COMPACTED_RESULT_MARKER not in job.result

    # Field-by-field parity of the empty-scan contract shape across surfaces.
    assert _contract_subset(mcp_result) == _contract_subset(job.result)

    # Canonical empty shape: non-null collections, not ``None``, on BOTH sides.
    for result in (mcp_result, job.result):
        assert result["status"] == "no_agents_found"
        assert result["agents"] == []
        assert result["vulnerabilities"] == []
        assert result["blast_radius"] == result["blast_radii"] == []
        assert result["warnings"] == []
