"""JSON/SARIF/HTML export parity for CWPP ``workload_runtime_evidence`` (#4158 C)."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

from agent_bom.cloud.runtime_workload_evidence import (
    STATE_HAS_IOC,
    STATE_NO_SIGNAL,
    RuntimeEvidenceSource,
    RuntimeSignalType,
    RuntimeSourceRegistry,
    RuntimeWorkloadEvidenceIndex,
    RuntimeWorkloadSignal,
    attach_workload_runtime_evidence_to_finding_model,
    ingest_runtime_signals,
    no_runtime_signal_summary,
)
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    SQLiteRuntimeWorkloadEvidenceStore,
    set_runtime_workload_evidence_store,
)
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.html.document import to_html
from agent_bom.output.json_fmt import to_json
from agent_bom.output.sarif import to_sarif


def _workload_finding(*, with_ioc_summary: bool = False) -> Finding:
    finding = Finding(
        finding_type=FindingType.CIS_FAIL,
        source=FindingSource.CLOUD_CIS,
        asset=Asset(
            name="web",
            asset_type="cloud_resource",
            identifier="i-0abc",
            provider="aws",
            account_ref="aws:123456789012",
        ),
        severity="high",
        title="workload disk finding",
        description="demo",
        provider="aws",
        account_ref="aws:123456789012",
        evidence={"resource_id": "i-0abc", "provider": "aws"},
    )
    if with_ioc_summary:
        finding.workload_runtime_evidence = {
            "schema_version": "1.0",
            "state": STATE_HAS_IOC,
            "signal_count": 1,
            "clean_workload_assertion": False,
            "note": "Runtime evidence is additive and never a clean-workload claim.",
        }
    return finding


def _configure_default_store(monkeypatch, state_dir, *, tenant_id: str | None = None, ephemeral: bool = False) -> None:
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(state_dir))
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    if tenant_id is None:
        monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_TENANT_ID", tenant_id)
    if ephemeral:
        monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
    else:
        monkeypatch.delenv("AGENT_BOM_EPHEMERAL_STORE", raising=False)
    set_runtime_workload_evidence_store(None)


def _seed_ioc(db_path, *, tenant_id: str, dedup_key: str) -> None:
    writer = SQLiteRuntimeWorkloadEvidenceStore(db_path)
    assert (
        writer.put_batch(
            [
                RuntimeWorkloadSignal(
                    tenant_id=tenant_id,
                    provider="aws",
                    account_id="123456789012",
                    workload_ref="i-0abc",
                    signal_type=RuntimeSignalType.IOC_DETECTION,
                    severity="high",
                    observed_at="2026-07-26T12:00:00Z",
                    source_id="edr-1",
                    source_kind="edr",
                    dedup_key=dedup_key,
                    title="known IOC",
                )
            ]
        )
        == 1
    )


def _export(finding: Finding) -> dict:
    report = AIBOMReport(generated_at=datetime.now(timezone.utc), tool_version="0.0.0", findings=[finding])
    return to_json(report)


def test_json_sarif_html_carry_preattached_workload_runtime_evidence() -> None:
    finding = _workload_finding(with_ioc_summary=True)
    report = AIBOMReport(generated_at=datetime.now(timezone.utc), tool_version="0.0.0", findings=[finding])

    payload = to_json(report)
    exported = next(row for row in payload["findings"] if row["id"] == finding.id)
    assert exported["workload_runtime_evidence"]["state"] == STATE_HAS_IOC
    assert exported["workload_runtime_evidence"]["clean_workload_assertion"] is False

    sarif = to_sarif(report)
    props = next(result["properties"] for result in sarif["runs"][0]["results"] if result["properties"].get("workload_runtime_evidence"))
    assert props["workload_runtime_evidence"]["state"] == STATE_HAS_IOC
    assert props["workload_runtime_evidence"]["clean_workload_assertion"] is False

    html = to_html(report)
    assert 'class="workload-runtime-evidence"' in html
    assert "Runtime IOC" in html
    assert "clean-workload assertion" in html


def test_export_enrichment_from_store_marks_no_signal_honestly(monkeypatch) -> None:
    store = InMemoryRuntimeWorkloadEvidenceStore()
    set_runtime_workload_evidence_store(store)
    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "tenant-export")
    try:
        registry = RuntimeSourceRegistry()
        registry.add(
            RuntimeEvidenceSource.register(
                source_id="edr-1",
                tenant_id="tenant-export",
                provider="aws",
                account_id="123456789012",
                kind="edr",
                secret="s3cr3t-token-value-1234",
            )
        )
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ingest_runtime_signals(
            registry=registry,
            source_id="edr-1",
            secret="s3cr3t-token-value-1234",
            raw_signals=[
                {
                    "workload_ref": "i-other",
                    "dedup_key": "evt-1",
                    "signal_type": "ioc_detection",
                    "severity": "high",
                    "observed_at": now,
                    "title": "other workload",
                }
            ],
            store=store,
        )

        finding = _workload_finding()
        report = AIBOMReport(generated_at=datetime.now(timezone.utc), tool_version="0.0.0", findings=[finding])
        payload = to_json(report)
        exported = next(row for row in payload["findings"] if row["id"] == finding.id)
        assert exported["workload_runtime_evidence"]["state"] == STATE_NO_SIGNAL
        assert exported["workload_runtime_evidence"]["clean_workload_assertion"] is False

        html = to_html(report)
        assert "No runtime signal" in html
    finally:
        set_runtime_workload_evidence_store(None)


def test_optional_enrichment_failure_does_not_suppress_core_findings(caplog) -> None:
    class UnavailableStore:
        def list_for_tenant(self, tenant_id: str, *, limit: int = 5000):
            del tenant_id, limit
            raise RuntimeError("postgresql://agent_bom_app:secret-value@db.internal/agent_bom unavailable")

    # Pin capture to the emitting logger. Under xdist worksteal, an earlier test
    # (e.g. setup_logging(level="ERROR")) can leave the agent_bom logger tree at
    # ERROR+, which filters this WARNING and empties caplog.text — the Python
    # 3.14 main failure mode for this assertion.
    evidence_logger = logging.getLogger("agent_bom.cloud.runtime_workload_evidence")
    prev_propagate = evidence_logger.propagate
    evidence_logger.propagate = True
    caplog.set_level(logging.WARNING, logger="agent_bom.cloud.runtime_workload_evidence")

    set_runtime_workload_evidence_store(UnavailableStore())  # type: ignore[arg-type]
    try:
        finding = _workload_finding()
        report = AIBOMReport(generated_at=datetime.now(timezone.utc), tool_version="0.0.0", findings=[finding])

        payload = to_json(report)

        assert any(row["id"] == finding.id for row in payload["findings"])
        assert "optional runtime workload evidence enrichment unavailable" in caplog.text
        assert "secret-value" not in caplog.text
    finally:
        evidence_logger.propagate = prev_propagate
        set_runtime_workload_evidence_store(None)


def test_optional_enrichment_does_not_create_missing_default_sqlite(monkeypatch, tmp_path, caplog) -> None:
    state_dir = tmp_path / "missing-state"
    _configure_default_store(monkeypatch, state_dir)

    evidence_logger = logging.getLogger("agent_bom.cloud.runtime_workload_evidence")
    previous_propagate = evidence_logger.propagate
    evidence_logger.propagate = True
    caplog.set_level(logging.WARNING, logger="agent_bom.cloud.runtime_workload_evidence")
    try:
        finding = _workload_finding()
        payload = _export(finding)

        assert any(row["id"] == finding.id for row in payload["findings"])
        assert not state_dir.exists()
        assert "optional runtime workload evidence enrichment unavailable" not in caplog.text
    finally:
        evidence_logger.propagate = previous_propagate
        set_runtime_workload_evidence_store(None)


def test_optional_enrichment_reads_existing_read_only_sqlite(monkeypatch, tmp_path, caplog) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    db_path = state_dir / "control-plane.db"
    _seed_ioc(db_path, tenant_id="tenant-read-only", dedup_key="evt-read-only")
    _configure_default_store(monkeypatch, state_dir, tenant_id="tenant-read-only")

    db_path.chmod(0o444)
    state_dir.chmod(0o555)
    try:
        finding = _workload_finding()
        payload = _export(finding)

        exported = next(row for row in payload["findings"] if row["id"] == finding.id)
        assert exported["workload_runtime_evidence"]["state"] == STATE_HAS_IOC
        assert "optional runtime workload evidence enrichment unavailable" not in caplog.text
    finally:
        state_dir.chmod(0o755)
        db_path.chmod(0o644)
        set_runtime_workload_evidence_store(None)


def test_optional_enrichment_skips_unreadable_default_sqlite_quietly(monkeypatch, tmp_path, caplog) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    db_path = state_dir / "control-plane.db"
    SQLiteRuntimeWorkloadEvidenceStore(db_path)
    _configure_default_store(monkeypatch, state_dir)

    original_connect = SQLiteRuntimeWorkloadEvidenceStore._connect

    def deny_read_only_open(store):
        if store._read_only:  # noqa: SLF001 - targeted failure injection
            raise sqlite3.OperationalError("unable to open database file")
        return original_connect(store)

    monkeypatch.setattr(SQLiteRuntimeWorkloadEvidenceStore, "_connect", deny_read_only_open)
    evidence_logger = logging.getLogger("agent_bom.cloud.runtime_workload_evidence")
    previous_propagate = evidence_logger.propagate
    evidence_logger.propagate = True
    caplog.set_level(logging.WARNING, logger="agent_bom.cloud.runtime_workload_evidence")
    try:
        finding = _workload_finding()
        payload = _export(finding)

        assert any(row["id"] == finding.id for row in payload["findings"])
        assert "optional runtime workload evidence enrichment unavailable" not in caplog.text
    finally:
        evidence_logger.propagate = previous_propagate
        set_runtime_workload_evidence_store(None)


def test_optional_enrichment_ephemeral_opt_out_ignores_stale_default_sqlite(monkeypatch, tmp_path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    db_path = state_dir / "control-plane.db"
    _seed_ioc(db_path, tenant_id="tenant-ephemeral", dedup_key="evt-stale")
    _configure_default_store(monkeypatch, state_dir, tenant_id="tenant-ephemeral", ephemeral=True)
    try:
        finding = _workload_finding()
        payload = _export(finding)

        exported = next(row for row in payload["findings"] if row["id"] == finding.id)
        assert "workload_runtime_evidence" not in exported
    finally:
        set_runtime_workload_evidence_store(None)


def test_attach_model_uses_asset_identity() -> None:
    finding = _workload_finding()
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [])
    # Empty index must not annotate (callers use optional_* which returns None).
    assert attach_workload_runtime_evidence_to_finding_model(finding, index) is False

    summary = no_runtime_signal_summary()
    # Non-empty index with no matching signals still annotates no_runtime_signal.
    index._by_workload["aws\x1f123456789012\x1fi-other"] = []  # type: ignore[attr-defined]
    # Force non-empty via a real signal-shaped key presence:
    index._by_workload["aws\x1f123456789012\x1fi-other"] = []  # noqa: SLF001
    # RuntimeWorkloadEvidenceIndex.is_empty checks the map; empty lists still count.
    assert index.is_empty() is False
    assert attach_workload_runtime_evidence_to_finding_model(finding, index) is True
    assert finding.workload_runtime_evidence == summary
