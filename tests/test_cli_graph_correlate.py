from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main


class FakeCorrelationClient:
    calls: list[tuple[str, dict[str, Any]]] = []
    base_url = "http://127.0.0.1:8422"

    def __init__(self, **kwargs: Any) -> None:
        pass

    def close(self) -> None:
        self.__class__.calls.append(("close", {}))

    def create_graph_correlation(self, **kwargs: Any) -> dict[str, Any]:
        self.__class__.calls.append(("create", kwargs))
        return _run("pending")

    def graph_correlation(self, correlation_id: str) -> dict[str, Any]:
        self.__class__.calls.append(("status", {"correlation_id": correlation_id}))
        return _run("complete")

    def list_graph_correlations(self, **kwargs: Any) -> dict[str, Any]:
        self.__class__.calls.append(("list", kwargs))
        return {"items": [_run("complete")], "count": 1}

    def graph_snapshots(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.__class__.calls.append(("snapshots", kwargs))
        return [
            {
                "scan_id": "repo-scan",
                "snapshot_kind": "scan",
                "created_at": "2026-09-03T12:00:00+00:00",
                "node_count": 12,
                "edge_count": 8,
            },
            {
                "scan_id": "empty-scan",
                "snapshot_kind": "scan",
                "created_at": "2026-09-03T12:00:00+00:00",
                "node_count": 0,
                "edge_count": 0,
            },
            {
                "scan_id": "prior-correlation",
                "snapshot_kind": "correlation",
                "created_at": "2026-09-03T12:00:00+00:00",
                "node_count": 20,
                "edge_count": 14,
            },
        ]


def _run(status: str) -> dict[str, Any]:
    return {
        "correlation_id": "corr-1",
        "name": "reference proof",
        "status": status,
        "max_age_hours": 168,
        "allow_stale": False,
        "input_manifest": [
            {"scan_id": "image", "freshness": "fresh", "verification": "verified", "node_count": 12, "edge_count": 8},
            {"scan_id": "runtime", "freshness": "fresh", "verification": "verified", "node_count": 3, "edge_count": 2},
        ],
        "receipt_verification": {"status": "verified", "verified": 2, "total": 2},
        "result_manifest": {
            "output": {"scan_id": "corr-1", "node_count": 14, "edge_count": 12},
            "analysis": {"attack_path_count": 2, "exposure_path_count": 1, "limitations": ["bounded_to_500000_edges"]},
            "correlation_merge": {"conflict_count": 1},
        },
        "output_scan_id": "corr-1" if status == "complete" else "",
        "failure_code": "",
    }


def _install(monkeypatch) -> type[FakeCorrelationClient]:
    FakeCorrelationClient.calls = []
    monkeypatch.setattr("agent_bom.cli._findings_group.AgentBomClient", FakeCorrelationClient)
    return FakeCorrelationClient


def test_graph_correlate_create_wait_table(monkeypatch) -> None:
    fake = _install(monkeypatch)

    result = CliRunner().invoke(
        main,
        [
            "graph-correlate",
            "create",
            "--name",
            "reference proof",
            "--scan-id",
            "image",
            "--scan-id",
            "runtime",
            "--max-age-hours",
            "168",
            "--idempotency-key",
            "idem-1",
            "--wait",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "corr-1\tcomplete\t2\tfresh\tverified\t1\tcorr-1\t2\t1\tbounded_to_500000_edges" in result.output
    assert fake.calls[:2] == [
        (
            "create",
            {
                "name": "reference proof",
                "scan_ids": ["image", "runtime"],
                "max_age_hours": 168,
                "allow_stale": False,
                "idempotency_key": "idem-1",
            },
        ),
        ("status", {"correlation_id": "corr-1"}),
    ]


def test_graph_correlate_status_json(monkeypatch) -> None:
    _install(monkeypatch)
    result = CliRunner().invoke(main, ["graph-correlate", "status", "corr-1", "--format", "json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["result_manifest"]["correlation_merge"]["conflict_count"] == 1


def test_graph_correlate_list_table(monkeypatch) -> None:
    _install(monkeypatch)
    result = CliRunner().invoke(main, ["graph-correlate", "list", "--limit", "25"])

    assert result.exit_code == 0, result.output
    assert "corr-1\tcomplete" in result.output


def test_graph_correlate_inputs_lists_only_eligible_source_snapshots(monkeypatch) -> None:
    fake = _install(monkeypatch)

    result = CliRunner().invoke(main, ["graph-correlate", "inputs", "--limit", "25"])

    assert result.exit_code == 0, result.output
    assert "scan_id\tcreated_at\tnodes\tedges" in result.output
    assert "repo-scan\t2026-09-03T12:00:00+00:00\t12\t8" in result.output
    assert "empty-scan" not in result.output
    assert "prior-correlation" not in result.output
    assert fake.calls[0] == ("snapshots", {"limit": 25, "window_days": None})


def test_graph_correlate_requires_two_distinct_snapshots(monkeypatch) -> None:
    _install(monkeypatch)
    result = CliRunner().invoke(
        main,
        ["graph-correlate", "create", "--name", "bad", "--scan-id", "same", "--scan-id", "same", "--max-age-hours", "24"],
    )

    assert result.exit_code != 0
    assert "distinct" in result.output.lower()
