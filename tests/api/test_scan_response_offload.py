"""Regression coverage for large full-result scan responses."""

from __future__ import annotations

from functools import partial
from typing import cast

import pytest
from starlette.requests import Request

from agent_bom.api.models import ScanJob, ScanRequest


@pytest.mark.anyio
async def test_get_scan_offloads_full_result_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Full AI-BOM sanitization must not run on the server event-loop thread."""
    from agent_bom.api.routes import scan as scan_routes

    job = ScanJob(
        job_id="large-result",
        created_at="2026-08-28T00:00:00Z",
        request=ScanRequest(),
        result={"findings": [], "summary": {"total_findings": 0}},
    )
    offloaded: list[partial[ScanJob]] = []

    async def fake_load(_request: Request, _job_id: str) -> ScanJob:
        return job

    async def fake_run_sync(fn: partial[ScanJob]) -> ScanJob:
        offloaded.append(fn)
        return fn()

    monkeypatch.setattr(scan_routes, "_load_job_for_request", fake_load)
    monkeypatch.setattr(scan_routes.anyio.to_thread, "run_sync", fake_run_sync)

    response = await scan_routes.get_scan(cast(Request, object()), job.job_id)

    assert response.job_id == job.job_id
    assert len(offloaded) == 1
    assert offloaded[0].func is scan_routes._job_response_payload
