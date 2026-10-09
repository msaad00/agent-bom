"""Golden characterization of the API scan pipeline runner (``_run_scan_sync``).

Each scenario drives one request shape through the real runner with network,
persistence and side-effect collaborators stubbed, then pins the final job
state, the normalized result, the step-event stream and the order in which
collaborators were called. The golden is recorded from unmodified code so any
structural refactor of the runner must reproduce it byte for byte.

Regenerate (only for an intended behaviour change)::

    AGENT_BOM_UPDATE_SCAN_PIPELINE_GOLDENS=1 pytest tests/test_scan_pipeline_characterization.py
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, TransportType, Vulnerability

GOLDEN = Path(__file__).parent / "fixtures" / "scan_pipeline_characterization.json"
UPDATE = os.environ.get("AGENT_BOM_UPDATE_SCAN_PIPELINE_GOLDENS") == "1"

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_VOLATILE_KEYS = {"duration_ms", "elapsed_ms", "scan_duration_seconds", "duration_seconds", "generated_at", "timestamp"}


class _Trace:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def add(self, name: str) -> None:
        if self.calls and self.calls[-1].split(" x")[0] == name:
            count = int(self.calls[-1].rsplit(" x", 1)[1]) if " x" in self.calls[-1] else 1
            self.calls[-1] = f"{name} x{count + 1}"
            return
        self.calls.append(name)


class _Store:
    retains_job_objects_in_memory = True

    def __init__(self, trace: _Trace, *, fail: bool = False) -> None:
        self._trace = trace
        self._fail = fail

    def put(self, job: ScanJob) -> None:
        self._trace.add(f"store.put:{job.status.value}")
        if self._fail:
            raise OSError("disk full")


class _Analytics:
    def __init__(self, trace: _Trace) -> None:
        self._trace = trace

    def __getattr__(self, name: str) -> Callable[..., None]:
        def _record(*_args: Any, **_kwargs: Any) -> None:
            self._trace.add(f"analytics.{name}")

        return _record


class _AssetTracker:
    def __init__(self, trace: _Trace, **_kwargs: Any) -> None:
        self._trace = trace

    def __enter__(self) -> _AssetTracker:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def record_scan(self, _report: dict) -> dict:
        self._trace.add("asset_tracker.record_scan")
        return {"summary": {"new_count": 1, "resolved_count": 0, "total_open": 1}}


def _agent(name: str = "api-agent") -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path=f"/fixture/{name}",
        mcp_servers=[
            MCPServer(
                name=f"{name}-server",
                command="npx",
                args=[],
                env={},
                transport=TransportType.STDIO,
                packages=[Package(name="express", version="4.18.2", ecosystem="npm")],
            )
        ],
    )


def _blast(agents: list[Agent], severity: Severity = Severity.HIGH) -> list[BlastRadius]:
    agent = agents[0]
    server = agent.mcp_servers[0]
    pkg = server.packages[0]
    vuln = Vulnerability(id="CVE-2026-0001", summary="test vuln", severity=severity, cvss_score=8.1, advisory_sources=["osv"])
    pkg.vulnerabilities = [vuln]
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    return [br]


def _normalize(value: Any, root: str) -> Any:
    if isinstance(value, dict):
        return {key: ("<VOLATILE>" if key in _VOLATILE_KEYS else _normalize(item, root)) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize(item, root) for item in value]
    if isinstance(value, str):
        text = value.replace(root, "<ROOT>").replace(str(Path(__file__).resolve().parents[1]), "<REPO>")
        text = _TIMESTAMP.sub("<TS>", text)
        return _UUID.sub("<UUID>", text)
    if isinstance(value, float):
        return round(value, 6)
    return value


def _progress(lines: list[str], root: str) -> list[Any]:
    out: list[Any] = []
    for line in lines:
        try:
            out.append(_normalize(json.loads(line), root))
        except ValueError:
            out.append(_normalize(line, root))
    return out


def _install(monkeypatch: pytest.MonkeyPatch, trace: _Trace, scenario: dict[str, Any]) -> None:
    discovered: list[Agent] = scenario.get("discovered", [])

    def _discover_all(*_args: Any, **kwargs: Any) -> list[Agent]:
        trace.add(f"discover_all:{'project' if kwargs.get('project_dir') else 'host'}")
        return list(discovered)

    def _scan(agents: list[Agent], enable_enrichment: bool = False, offline: bool = False, **_kwargs: Any) -> list[BlastRadius]:
        trace.add(f"scan_agents_sync:enrich={enable_enrichment}:offline={offline}")
        behaviour = scenario.get("scan", "ok")
        if behaviour == "raise" or (behaviour == "raise-once" and enable_enrichment):
            raise RuntimeError("osv unavailable token=secret")
        return _blast(agents, scenario.get("severity", Severity.HIGH))

    def _trend(*_args: Any, **_kwargs: Any) -> bool:
        trace.add("trend")
        return True

    def _graph(*_args: Any, **_kwargs: Any) -> None:
        trace.add("persist_graph")
        if scenario.get("graph_fails"):
            raise RuntimeError("graph store down")

    def _suppress(*_args: Any, **_kwargs: Any) -> dict[str, int]:
        trace.add("suppression")
        return {"suppressed": scenario.get("suppressed", 0)}

    monkeypatch.setattr("agent_bom.api.pipeline._get_store", lambda: _Store(trace, fail=scenario.get("store_fails", False)))
    monkeypatch.setattr("agent_bom.api.pipeline._get_analytics_store", lambda: _Analytics(trace))
    monkeypatch.setattr("agent_bom.api.pipeline._persist_graph_snapshot", _graph)
    monkeypatch.setattr("agent_bom.api.pipeline._sync_scan_agents_to_fleet", lambda *_a, **_k: trace.add("fleet_sync"))
    monkeypatch.setattr("agent_bom.discovery.discover_all", _discover_all)
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", _scan)
    monkeypatch.setattr("agent_bom.api.trend_recording.record_scan_trend_best_effort", _trend)
    monkeypatch.setattr("agent_bom.asset_tracker.AssetTracker", lambda **kw: _AssetTracker(trace, **kw))
    monkeypatch.setattr("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: "local-1")
    monkeypatch.setattr(
        "agent_bom.db.adoption_events.record_scan_completion_best_effort", lambda **kw: trace.add(f"adoption:{kw['outcome']}")
    )
    monkeypatch.setattr("agent_bom.api.scan_job_reconciliation.reconcile_scan_jobs_active", lambda _store: trace.add("reconcile"))
    monkeypatch.setattr("agent_bom.scan_enrichment.enrich_report_with_estate_discovery", lambda _report: trace.add("estate_enrichment"))
    monkeypatch.setattr("agent_bom.suppression_rules.apply_tenant_suppression_rules", _suppress)
    monkeypatch.setattr("agent_bom.db.sync.sync_db", lambda **_k: trace.add("sync_db"))
    monkeypatch.setattr("agent_bom.db.schema.db_freshness_days", lambda: None)
    monkeypatch.setattr("agent_bom.image.scan_image", lambda _ref: (_ for _ in ()).throw(RuntimeError("registry token=secret")))


def _scenarios(root: Path) -> dict[str, dict[str, Any]]:
    project = root / "project"
    project.mkdir()
    (project / "app.py").write_text("import json\n\n\ndef handler(payload):\n    return json.dumps(payload)\n")
    empty = root / "empty"
    empty.mkdir()
    bad_inventory = root / "inventory.json"
    bad_inventory.write_text("{not json")
    return {
        "cancelled_before_start": {"request": ScanRequest(), "cancelled": True},
        "dry_run": {"request": ScanRequest(dry_run=True, images=["registry.example/app:1"])},
        "no_agents": {"request": ScanRequest()},
        "findings_only_static_project": {"request": ScanRequest(agent_projects=[str(project)])},
        "full_scan_with_side_effects": {
            "request": ScanRequest(agent_projects=[str(empty)], enrich=True, auto_update_db=True),
            "discovered": [_agent()],
            "suppressed": 1,
        },
        "scope_and_severity_filters": {
            "request": ScanRequest(
                agent_projects=[str(empty)],
                scope_agents=["keep-*"],
                exclude_servers=["*-drop"],
                min_severity="critical",
            ),
            "discovered": [_agent("keep-me"), _agent("other")],
        },
        "scan_retry_without_enrichment": {
            "request": ScanRequest(agent_projects=[str(empty)], enrich=True),
            "discovered": [_agent()],
            "scan": "raise-once",
        },
        "offline_scan_error": {
            "request": ScanRequest(agent_projects=[str(empty)], offline=True, enrich=True),
            "discovered": [_agent()],
            "scan": "raise",
        },
        "online_scan_fails_closed": {
            "request": ScanRequest(agent_projects=[str(empty)]),
            "discovered": [_agent()],
            "scan": "raise",
        },
        "no_scan_supplied_findings": {
            "request": ScanRequest(agent_projects=[str(empty)], no_scan=True),
            "discovered": [_agent()],
        },
        "image_error_and_graph_failure": {
            "request": ScanRequest(images=["registry.example/app:1"], discover_host=False),
            "graph_fails": True,
        },
        "image_error_with_agent_and_graph_failure": {
            "request": ScanRequest(images=["registry.example/app:1"], agent_projects=[str(empty)]),
            "discovered": [_agent()],
            "graph_fails": True,
        },
        "inventory_load_failure": {"request": ScanRequest(inventory=str(bad_inventory))},
        "store_put_failure": {"request": ScanRequest(agent_projects=[str(empty)]), "discovered": [_agent()], "store_fails": True},
        "sarif_format": {"request": ScanRequest(agent_projects=[str(empty)], format="sarif"), "discovered": [_agent()]},
    }


def _run(monkeypatch: pytest.MonkeyPatch, name: str, scenario: dict[str, Any], root: Path) -> dict[str, Any]:
    trace = _Trace()
    with monkeypatch.context() as patch:
        _install(patch, trace, scenario)
        job = ScanJob(job_id=f"char-{name}", tenant_id="tenant-char", created_at="2026-10-08T00:00:00Z", request=scenario["request"])
        if scenario.get("cancelled"):
            job.status = JobStatus.CANCELLED
        _run_scan_sync(job)
    document = job.result_document
    if isinstance(document, str):
        document_shape: Any = {"type": "str", "length_bucket": len(document) > 0}
    elif isinstance(document, dict):
        document_shape = {"type": "dict", "keys": sorted(document)}
    else:
        document_shape = None
    return _normalize(
        {
            "status": job.status.value,
            "error": job.error,
            "started": job.started_at is not None,
            "completed": job.completed_at is not None,
            "progress": _progress(job.progress, str(root)),
            "result": job.result,
            "result_document": document_shape,
            "calls": trace.calls,
        },
        str(root),
    )


def test_run_scan_sync_matches_golden(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AGENT_BOM_REPO_SCAN_TOKEN", raising=False)
    root = tmp_path.resolve()
    results = {name: _run(monkeypatch, name, scenario, root) for name, scenario in _scenarios(root).items()}
    if UPDATE:
        GOLDEN.write_text(json.dumps(results, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert sorted(results) == sorted(expected)
    for name in expected:
        assert results[name] == expected[name], name
