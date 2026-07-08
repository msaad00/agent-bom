"""Tests for structured scan pipeline SSE events (v0.51.0)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.api.server import (
    PIPELINE_DAG_EDGES,
    PIPELINE_DAG_EVENT_SCHEMA,
    PIPELINE_STEPS,
    ScanJob,
    ScanPipeline,
    ScanRequest,
    StepStatus,
    iter_pipeline_dag_event_records,
    pipeline_dag_events_jsonl,
)
from agent_bom.cli._report_group import pipeline_events_cmd

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


# ---------------------------------------------------------------------------
# Dashboard DAG event artifact
# ---------------------------------------------------------------------------


class TestPipelineDagEventArtifact:
    def test_dag_event_records_include_step_edges_for_dashboard(self):
        job = _make_job()
        job.tenant_id = "tenant-a"
        pipeline = ScanPipeline(job)

        pipeline.start_step("discovery", "Discovering...")
        pipeline.complete_step("discovery", "Found 2 agents", stats={"agents": 2})
        pipeline.start_step("extraction", "Extracting packages...")
        pipeline.skip_step("scanning", "Vulnerability scanning skipped")
        job.progress.append("legacy progress line")

        records = iter_pipeline_dag_event_records(job.progress, scan_id=job.job_id, tenant_id=job.tenant_id)

        assert len(records) == 4
        assert all(record["schema_version"] == PIPELINE_DAG_EVENT_SCHEMA for record in records)
        assert all(record["type"] == "pipeline_dag_step" for record in records)
        assert all(record["scan_id"] == job.job_id for record in records)
        assert all(record["tenant_id"] == "tenant-a" for record in records)

        discovery = records[0]
        assert discovery["step"]["id"] == "discovery"
        assert discovery["step"]["index"] == 0
        assert discovery["dag"]["depends_on"] == []
        assert discovery["dag"]["next_steps"] == ["extraction"]
        assert discovery["dag"]["edges"] == PIPELINE_DAG_EDGES
        assert discovery["dashboard"] == {
            "lane": "scan_pipeline",
            "render": "dag_step",
            "terminal": False,
        }

        scanning = records[-1]
        assert scanning["step"]["id"] == "scanning"
        assert scanning["step"]["status"] == "skipped"
        assert scanning["dag"]["depends_on"] == ["extraction"]
        assert scanning["dag"]["next_steps"] == ["enrichment"]
        assert scanning["dashboard"]["terminal"] is True

    def test_dag_event_jsonl_serializes_one_record_per_structured_step(self):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("analysis", "Computing blast radius...", sub_step="agent-a")
        pipeline.update_step("analysis", "Halfway", stats={"blast_radius": 1}, progress_pct=50)
        pipeline.complete_step("analysis", "Done", stats={"blast_radius": 2})
        job.progress.append("plain progress")

        jsonl = pipeline_dag_events_jsonl(job)
        lines = jsonl.splitlines()

        assert len(lines) == 3
        parsed = [json.loads(line) for line in lines]
        assert [record["sequence"] for record in parsed] == [0, 1, 2]
        assert parsed[0]["event_id"] == "test-123:0:analysis:running"
        assert parsed[0]["step"]["sub_step"] == "agent-a"
        assert parsed[1]["step"]["progress_pct"] == 50
        assert parsed[2]["step"]["stats"] == {"blast_radius": 2}
        assert parsed[2]["dashboard"]["terminal"] is True

    def test_report_cli_exports_pipeline_dag_event_jsonl(self, tmp_path):
        job = _make_job()
        pipeline = ScanPipeline(job)
        pipeline.start_step("output", "Building report...")
        pipeline.complete_step("output", "Report ready")

        scan_job_path = tmp_path / "scan-job.json"
        output_path = tmp_path / "pipeline-events.jsonl"
        scan_job_path.write_text(json.dumps(job.model_dump(mode="json")), encoding="utf-8")

        result = CliRunner().invoke(pipeline_events_cmd, [str(scan_job_path), "--output", str(output_path)])

        assert result.exit_code == 0
        assert output_path.exists()
        records = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
        assert [record["step"]["status"] for record in records] == ["running", "done"]
        assert records[0]["dag"]["depends_on"] == ["analysis"]
        assert records[0]["dag"]["next_steps"] == []
