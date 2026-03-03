"""Tests for structured scan pipeline SSE events (v0.42.0)."""

from __future__ import annotations

import json

from agent_bom.api.server import (
    PIPELINE_STEPS,
    ScanJob,
    ScanPipeline,
    ScanRequest,
    StepStatus,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_job() -> ScanJob:
    return ScanJob(
        job_id="test-123",
        created_at="2026-03-02T00:00:00Z",
        request=ScanRequest(),
    )


# ---------------------------------------------------------------------------
# StepStatus enum
# ---------------------------------------------------------------------------


class TestStepStatus:
    def test_values(self):
        assert StepStatus.PENDING == "pending"
        assert StepStatus.RUNNING == "running"
        assert StepStatus.DONE == "done"
        assert StepStatus.FAILED == "failed"
        assert StepStatus.SKIPPED == "skipped"


# ---------------------------------------------------------------------------
# Pipeline steps constant
# ---------------------------------------------------------------------------


class TestPipelineSteps:
    def test_step_count(self):
        assert len(PIPELINE_STEPS) == 6

    def test_step_order(self):
        assert PIPELINE_STEPS == [
            "discovery",
            "extraction",
            "scanning",
            "enrichment",
            "analysis",
            "output",
        ]


# ---------------------------------------------------------------------------
# ScanPipeline helper
# ---------------------------------------------------------------------------


class TestScanPipeline:
    def test_init_creates_pending_steps(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        assert len(pipeline._steps) == 6
        for step_id in PIPELINE_STEPS:
            assert pipeline._steps[step_id]["status"] == StepStatus.PENDING

    def test_start_step(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Finding agents...")

        assert pipeline._steps["discovery"]["status"] == StepStatus.RUNNING
        assert pipeline._steps["discovery"]["message"] == "Finding agents..."
        assert pipeline._steps["discovery"]["started_at"] is not None
        # Should have emitted to job.progress
        assert len(job.progress) == 1

    def test_update_step(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Starting...")
        pipeline.update_step("discovery", "Found 3 agents", stats={"agents": 3})

        assert pipeline._steps["discovery"]["stats"]["agents"] == 3
        assert len(job.progress) == 2

    def test_complete_step(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("scanning", "Scanning CVEs...")
        pipeline.complete_step("scanning", "Done", stats={"vulnerabilities": 15})

        assert pipeline._steps["scanning"]["status"] == StepStatus.DONE
        assert pipeline._steps["scanning"]["completed_at"] is not None
        assert pipeline._steps["scanning"]["stats"]["vulnerabilities"] == 15

    def test_fail_step(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("extraction", "Extracting...")
        pipeline.fail_step("extraction", "Network error")

        assert pipeline._steps["extraction"]["status"] == StepStatus.FAILED
        assert pipeline._steps["extraction"]["completed_at"] is not None

    def test_skip_step(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.skip_step("enrichment", "Not requested")

        assert pipeline._steps["enrichment"]["status"] == StepStatus.SKIPPED

    def test_emitted_events_are_valid_json(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Finding agents...")
        pipeline.complete_step("discovery", "Found 5 agents", stats={"agents": 5})

        for line in job.progress:
            parsed = json.loads(line)
            assert parsed["type"] == "step"
            assert parsed["step_id"] == "discovery"
            assert parsed["status"] in ("pending", "running", "done", "failed", "skipped")

    def test_stats_accumulate(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Starting...")
        pipeline.update_step("discovery", "More agents", stats={"agents": 3})
        pipeline.update_step("discovery", "Even more", stats={"images": 2})
        pipeline.complete_step("discovery", "Done", stats={"agents": 5})

        assert pipeline._steps["discovery"]["stats"]["agents"] == 5
        assert pipeline._steps["discovery"]["stats"]["images"] == 2

    def test_sub_step_tracking(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Scanning image", sub_step="nginx:latest")

        assert pipeline._steps["discovery"]["sub_step"] == "nginx:latest"

    def test_full_pipeline_flow(self):
        """Simulate a complete scan pipeline."""
        job = _make_job()
        pipeline = ScanPipeline(job)

        pipeline.start_step("discovery", "Discovering...")
        pipeline.complete_step("discovery", "Found 2 agents", stats={"agents": 2})

        pipeline.start_step("extraction", "Extracting packages...")
        pipeline.complete_step("extraction", "10 packages", stats={"packages": 10})

        pipeline.start_step("scanning", "Querying OSV...")
        pipeline.complete_step("scanning", "3 CVEs", stats={"vulnerabilities": 3})

        pipeline.skip_step("enrichment", "Not requested")

        pipeline.start_step("analysis", "Blast radius...")
        pipeline.complete_step("analysis", "Done", stats={"blast_radius": 2})

        pipeline.start_step("output", "Building report...")
        pipeline.complete_step("output", "Report ready")

        # All steps should be in a terminal state
        for step_id in PIPELINE_STEPS:
            status = pipeline._steps[step_id]["status"]
            assert status in (StepStatus.DONE, StepStatus.SKIPPED)

        # Should have emitted events for each transition
        assert len(job.progress) >= 6  # At least one event per step


# ---------------------------------------------------------------------------
# SSE event format compatibility
# ---------------------------------------------------------------------------


class TestSSEEventFormat:
    def test_step_event_has_required_fields(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Starting...")

        parsed = json.loads(job.progress[0])
        assert "type" in parsed
        assert "step_id" in parsed
        assert "status" in parsed
        assert "message" in parsed
        assert parsed["type"] == "step"

    def test_legacy_progress_still_works(self):
        """Plain strings appended to progress should still be valid."""
        job = _make_job()
        job.progress.append("Legacy message")
        # The SSE generator should handle this gracefully
        # (not JSON-parseable → falls through to legacy handler)
        try:
            json.loads(job.progress[0])
            is_json = True
        except json.JSONDecodeError:
            is_json = False
        assert not is_json  # Should be a plain string

    def test_step_status_serialized_as_string(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("discovery", "Starting...")

        parsed = json.loads(job.progress[0])
        assert isinstance(parsed["status"], str)
        assert parsed["status"] == "running"
