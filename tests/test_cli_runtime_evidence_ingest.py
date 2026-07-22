"""CLI/MCP helper for CWPP runtime evidence ingest (#4158 stage 4)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli._cloud_group import cloud_group
from agent_bom.cloud.runtime_workload_evidence import (
    RuntimeEvidenceSource,
    RuntimeSourceRegistry,
    ingest_runtime_signals_payload,
    set_runtime_source_registry,
)
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    set_runtime_workload_evidence_store,
)

SOURCE_SECRET = "s3cr3t-token-value-1234"


def setup_function() -> None:
    registry = RuntimeSourceRegistry()
    registry.add(
        RuntimeEvidenceSource.register(
            source_id="edr-1",
            tenant_id="tenant-alpha",
            provider="aws",
            account_id="123456789012",
            kind="edr",
            secret=SOURCE_SECRET,
        )
    )
    set_runtime_source_registry(registry)
    set_runtime_workload_evidence_store(InMemoryRuntimeWorkloadEvidenceStore())


def teardown_function() -> None:
    set_runtime_source_registry(None)
    set_runtime_workload_evidence_store(None)


def _signal(workload_ref: str = "i-0abc", dedup_key: str = "evt-1") -> dict:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "workload_ref": workload_ref,
        "dedup_key": dedup_key,
        "signal_type": "ioc_detection",
        "severity": "high",
        "observed_at": now,
        "title": "demo ioc",
    }


def test_ingest_runtime_signals_payload_accepts_wrapped_list() -> None:
    result = ingest_runtime_signals_payload(
        source_id="edr-1",
        secret=SOURCE_SECRET,
        payload={"signals": [_signal()]},
        persist=True,
    )
    assert result.persisted == 1
    assert result.accepted


def test_cli_runtime_evidence_ingest_persists(tmp_path: Path) -> None:
    path = tmp_path / "signals.json"
    path.write_text(json.dumps([_signal(dedup_key="cli-1")]), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        cloud_group,
        [
            "runtime-evidence-ingest",
            "--source-id",
            "edr-1",
            "--secret",
            SOURCE_SECRET,
            "--file",
            str(path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "persisted=1" in result.output


def test_cli_runtime_evidence_ingest_auth_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "signals.json"
    path.write_text(json.dumps([_signal(dedup_key="cli-2")]), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        cloud_group,
        [
            "runtime-evidence-ingest",
            "--source-id",
            "edr-1",
            "--secret",
            "wrong-secret",
            "--file",
            str(path),
        ],
    )
    assert result.exit_code == 1
    assert "authentication failed" in result.output
