"""Explicit "All regions" affordance for cloud connections (issue #3736).

A connection may carry the ``all`` sentinel in ``regions`` to request an
estate-wide multi-region scan. The route validation accepts + normalizes it
(rejecting a mix with specific regions), and the AWS scan dispatch fans out via
``discover_inventory_all_regions`` instead of scanning a single region.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import HTTPException

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.api.routes import cloud_connections as routes


def _record(regions: list[str]) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id=str(uuid.uuid4()),
        tenant_id="t1",
        provider="aws",
        display_name="prod",
        role_ref="arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id_encrypted="",
        regions=regions,
        status="pending",
        created_at="2026-06-26T00:00:00+00:00",
        updated_at="2026-06-26T00:00:00+00:00",
    )


class TestValidateRegions:
    def test_all_sentinel_is_accepted_and_normalized(self) -> None:
        assert routes._validate_regions(["all"]) == ["all"]
        assert routes._validate_regions(["ALL"]) == ["all"]

    def test_specific_regions_still_pass(self) -> None:
        assert routes._validate_regions(["us-east-1", "eu-west-1"]) == ["us-east-1", "eu-west-1"]

    def test_all_cannot_be_mixed_with_specific_regions(self) -> None:
        with pytest.raises(HTTPException) as exc:
            routes._validate_regions(["all", "us-east-1"])
        assert exc.value.status_code == 400

    def test_invalid_region_still_rejected(self) -> None:
        with pytest.raises(HTTPException):
            routes._validate_regions(["not-a-region"])


class TestAwsScanFansOutOnAllRegions:
    def _patch_common(self, monkeypatch: pytest.MonkeyPatch, calls: dict[str, Any]) -> None:
        from agent_bom.cloud import aws_inventory, connection_broker

        class _Sess:
            region_name = "us-east-1"

        monkeypatch.setattr(connection_broker, "broker_session", lambda record, session_name="": _Sess())

        def _single(**kwargs: Any) -> dict[str, Any]:
            calls["single_region"] = kwargs.get("region")
            calls["single"] = True
            return {"provider": "aws", "status": "ok"}

        def _multi(**kwargs: Any) -> dict[str, Any]:
            calls["multi"] = True
            calls["multi_session"] = kwargs.get("session")
            return {"provider": "aws", "status": "ok", "region": "multi:us-east-1"}

        monkeypatch.setattr(aws_inventory, "discover_inventory", _single)
        monkeypatch.setattr(aws_inventory, "discover_inventory_all_regions", _multi)

        from agent_bom.cloud import aws_cis_benchmark

        class _Cis:
            def to_dict(self) -> dict[str, Any]:
                return {"benchmark": "cis", "passed": 0, "failed": 0, "total": 0, "pass_rate": 0}

        monkeypatch.setattr(aws_cis_benchmark, "run_benchmark", lambda **_kw: _Cis())
        monkeypatch.setattr(routes, "_persist_connection_report", lambda record, tenant_id, report: "scan-123")

    def test_all_regions_uses_multi_region_discovery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, Any] = {}
        self._patch_common(monkeypatch, calls)
        result = routes._run_aws_connection_scan(_record(["all"]), "t1")
        assert calls.get("multi") is True
        assert calls.get("single") is None
        assert calls.get("multi_session") is not None  # brokered session threaded in
        assert result["scan_id"] == "scan-123"

    def test_single_region_uses_single_discovery(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict[str, Any] = {}
        self._patch_common(monkeypatch, calls)
        routes._run_aws_connection_scan(_record(["us-east-1"]), "t1")
        assert calls.get("single") is True
        assert calls.get("multi") is None
        assert calls.get("single_region") == "us-east-1"
