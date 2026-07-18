"""Honest truncation marking for the signed compliance evidence bundle (#3).

The bundle fetches audit evidence with a hard cap (``list_entries(limit=...)``)
and reported ``audit_event_count`` / integrity ``checked`` over the capped set
with NO ``truncated`` marker — a window with more events than the cap presented
partial evidence as the complete window inside a *signed* artifact.

These tests pin the fix: when the audit fetch hits the cap the signed bundle
carries ``audit_events_truncated: true`` + the cap; under the cap it is false.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.responses import JSONResponse

from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog, set_audit_log
from agent_bom.api.routes import compliance as compliance_routes


def setup_module() -> None:
    from tests.auth_helpers import enable_trusted_proxy_env

    enable_trusted_proxy_env()


def teardown_module() -> None:
    from tests.auth_helpers import disable_trusted_proxy_env

    disable_trusted_proxy_env()


def _request(tenant_id: str, actor: str = "ci-bot") -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant_id, api_key_name=actor))


def _seed_audit(tenant_id: str, count: int) -> InMemoryAuditLog:
    audit = InMemoryAuditLog()
    now = datetime.now(timezone.utc)
    for idx in range(count):
        audit.append(
            AuditEntry(
                entry_id=f"e{idx}",
                timestamp=(now - timedelta(minutes=count - idx)).isoformat(),
                action="scan.started",
                actor="ci-bot",
                resource=f"scan/{idx}",
                details={"tenant_id": tenant_id},
            )
        )
    set_audit_log(audit)
    return audit


_FULL = {
    "owasp_llm_top10": [
        {"control_id": "LLM01", "name": "Prompt Injection", "status": "pass", "tags": ["LLM01"]},
    ]
}


def _run_export(tenant: str) -> dict:
    req = _request(tenant)
    with patch.object(compliance_routes, "_tenant_jobs", return_value=[]):
        with patch.object(compliance_routes, "get_compliance", return_value=_FULL):
            resp = asyncio.run(compliance_routes.export_compliance_report(req, "owasp-llm"))
    assert isinstance(resp, JSONResponse)
    return json.loads(resp.body)


def test_bundle_marks_truncated_when_audit_fetch_hits_cap(monkeypatch):
    tenant = "tenant-trunc"
    _seed_audit(tenant, count=5)
    monkeypatch.setattr(compliance_routes, "_AUDIT_EVIDENCE_FETCH_LIMIT", 3)

    body = _run_export(tenant)

    scope = body["scope"]
    assert scope["audit_events_truncated"] is True
    assert scope["audit_event_limit"] == 3
    # Honest: the reported count never claims to be the complete window.
    assert scope["audit_event_count"] == 3
    assert body["audit_log_integrity"]["truncated"] is True

    # The truncation flag is inside the SIGNED canonical body.
    assert '"audit_events_truncated": true' in json.dumps(body, sort_keys=True)


def test_bundle_not_truncated_under_cap(monkeypatch):
    tenant = "tenant-untrunc"
    _seed_audit(tenant, count=2)
    monkeypatch.setattr(compliance_routes, "_AUDIT_EVIDENCE_FETCH_LIMIT", 10)

    body = _run_export(tenant)

    scope = body["scope"]
    assert scope["audit_events_truncated"] is False
    assert scope["audit_event_count"] == 2
    assert body["audit_log_integrity"]["truncated"] is False
