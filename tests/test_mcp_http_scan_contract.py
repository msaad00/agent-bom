import json

import pytest

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.pipeline import _now, _run_scan_sync
from agent_bom.mcp_tools.scanning import scan_impl


def _truncate(value: str) -> str:
    return value


async def _empty_scan_pipeline(*_args, **_kwargs):
    return [], [], [], []


def _contract_subset(payload: dict[str, object]) -> dict[str, object]:
    keys = {"status", "agents", "vulnerabilities", "blast_radius", "blast_radii", "warnings"}
    return {key: payload.get(key) for key in sorted(keys)}


@pytest.mark.asyncio
async def test_mcp_scan_no_agent_shape_matches_http_scan(monkeypatch):
    """Guard the shared scan response contract across MCP and HTTP surfaces."""
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda **_kwargs: [])

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

    assert _contract_subset(mcp_result) == _contract_subset(job.result)
    assert mcp_result["blast_radius"] == mcp_result["blast_radii"] == []
    assert job.result["blast_radius"] == job.result["blast_radii"] == []
