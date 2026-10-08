"""Retryable campaign membership reconciliation after committed evidence writes.

SQLite/Postgres triggers persist pending work atomically with source revisions.
Periodic polling recovers missed notifications and process restarts. Concurrent replicas use the store's revision write fence.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from agent_bom.api import foreground_activity
from agent_bom.api.campaign_store import (
    CampaignWorkflow,
    InMemoryCampaignStore,
    MembershipEvidence,
    SQLiteCampaignStore,
    get_campaign_store,
)
from agent_bom.api.risk_campaigns import derive_campaigns
from agent_bom.api.storage.campaign_revisions import CampaignAlreadyReconciledError, CampaignEvidenceChangedError
from agent_bom.api.tenant_worker import run_tenant_bound

_logger = logging.getLogger(__name__)
_cursor = ""


def notify_campaign_evidence(tenant_id: str, *, source_is_memory: bool = False) -> None:
    try:
        store = get_campaign_store()
        if isinstance(store, InMemoryCampaignStore):
            with store._lock:
                store.evidence_state.changed(tenant_id)
        elif source_is_memory and isinstance(store, SQLiteCampaignStore):
            # Default single-node evidence is ephemeral, while workflow state
            # is durable. No SQL source trigger can enqueue these writes.
            store.evidence_state.changed(tenant_id)
    except Exception:  # broad-except: Notifications must not fail evidence writes that have already committed.
        # Persistent source triggers retain pending work despite notification failure.
        _logger.warning("Campaign evidence notification deferred")


def reconcile_pending_campaigns(limit: int = 20) -> int:
    from starlette.requests import Request

    from agent_bom.api.routes.campaigns import _load_findings, _reconcile_campaigns, _source_incomplete

    global _cursor
    state = get_campaign_store().evidence_state
    tenants = state.pending_tenants(limit=limit, after=_cursor)
    if not tenants and _cursor:
        _cursor = ""
        tenants = state.pending_tenants(limit=limit)
    reconciled = 0
    for tenant_id in tenants:
        _cursor = tenant_id
        request = Request({"type": "http"})
        request.state.tenant_id = tenant_id
        request.state.api_key_name = "evidence-reconciler"

        def collect_and_reconcile() -> bool:
            source = _load_findings(request)
            if _source_incomplete(source):
                return False
            _reconcile_campaigns(request, source)
            return True

        try:
            reconciled += bool(run_tenant_bound(tenant_id, collect_and_reconcile))
        except Exception:  # broad-except: Provider or storage failures leave durable work pending for a later poll.
            # Leave the durable checkpoint pending. Do not log provider/DB errors.
            _logger.warning("Campaign evidence reconciliation deferred")
    return reconciled


def _campaigns(request: Any, source: dict[str, Any]) -> list[dict[str, Any]]:
    from agent_bom.api.routes.campaigns import CAMPAIGN_FINDING_LIMIT, _source_incomplete, _tenant

    tenant_id = _tenant(request)
    findings = source["findings"]
    incomplete = _source_incomplete(source)
    initial = derive_campaigns(
        findings, tenant_id=tenant_id, workflow_by_id={}, window_days=90, finding_limit=CAMPAIGN_FINDING_LIMIT, truncated=incomplete
    )
    memberships: dict[str, tuple[str, tuple[str, ...], str]] = {
        str(item["id"]): (
            str(item["membership_fingerprint"]),
            tuple(sorted(str(value) for value in item["finding_ids"])),
            str(item["title"])[:300],
        )
        for item in initial
    }
    before = {row.campaign_id: row for row in get_campaign_store().list(tenant_id)}
    if incomplete:
        workflows = {
            campaign_id: row
            for campaign_id, row in before.items()
            if row.active and row.membership_fingerprint == (memberships.get(campaign_id) or (None, ()))[0]
        }
        campaigns = derive_campaigns(
            findings,
            tenant_id=tenant_id,
            workflow_by_id=workflows,
            window_days=90,
            finding_limit=CAMPAIGN_FINDING_LIMIT,
            truncated=True,
        )
        for campaign in campaigns:
            # Assignment survives a partial collection; verification does not.
            assigned = before.get(str(campaign["id"]))
            if assigned and assigned.active:
                if assigned.owner is not None:
                    campaign["owner"] = assigned.owner
                campaign["sla_due_at"] = assigned.sla_due_at
            campaign["membership_complete"] = False
            campaign["membership_provisional"] = True
        return campaigns
    workflows = {}
    for campaign_id, (fingerprint, member_ids, title) in memberships.items():
        row = before.get(campaign_id)
        if row is None:
            continue
        if not row.active or row.membership_fingerprint != fingerprint or row.member_ids != member_ids:
            row = replace(
                row,
                active=True,
                membership_fingerprint=fingerprint,
                member_ids=member_ids,
                title=title,
                generation=row.generation + 1,
                version=row.version + 1,
                state="open",
                verification_status="unverified",
            )
        workflows[campaign_id] = row
    campaigns = derive_campaigns(
        findings,
        tenant_id=tenant_id,
        workflow_by_id=workflows,
        window_days=90,
        finding_limit=CAMPAIGN_FINDING_LIMIT,
        truncated=False,
    )
    for campaign in campaigns:
        campaign["membership_complete"] = True
        campaign["membership_provisional"] = False
    return campaigns


def _assert_source_fresh(request: Any, source: dict[str, Any]) -> None:
    from fastapi import HTTPException

    from agent_bom.api.routes.campaigns import _campaign_source_revision, _tenant

    if source.get("_source_revision") is not None and tuple(source["_source_revision"]) != _campaign_source_revision(request):
        raise HTTPException(status_code=409, detail="Campaign evidence changed; refresh and retry.")
    expected = source.get("_evidence_revision")
    if expected is not None and get_campaign_store().evidence_state.revision(_tenant(request)) != expected:
        raise HTTPException(status_code=409, detail="Campaign evidence changed; refresh and retry.")


def _reconcile_campaigns(request: Any, source: dict[str, Any]) -> list[dict[str, Any]]:
    """Apply a complete current collection; called only by evidence workers/writes."""
    from fastapi import HTTPException

    from agent_bom.api.routes.campaigns import _audit, _source_incomplete, _tenant

    _assert_source_fresh(request, source)
    campaigns = _campaigns(request, source)
    if _source_incomplete(source):
        return campaigns
    tenant_id = _tenant(request)
    memberships: dict[str, MembershipEvidence] = {
        str(item["id"]): (
            str(item["membership_fingerprint"]),
            tuple(sorted(str(value) for value in item["finding_ids"])),
            str(item["title"])[:300],
        )
        for item in campaigns
    }
    before = {row.campaign_id: row for row in get_campaign_store().list(tenant_id)}
    try:
        reconciled = get_campaign_store().reconcile_memberships(
            tenant_id, memberships, complete=True, evidence_revision=source.get("_evidence_revision")
        )
    except CampaignAlreadyReconciledError:
        return _campaigns(request, source)
    except CampaignEvidenceChangedError as exc:
        raise HTTPException(status_code=409, detail="Campaign evidence changed; refresh and retry.") from exc
    for row in reconciled:
        old = before.get(row.campaign_id)
        if old is None:
            _audit("risk_campaign.membership_observed", request, row.campaign_id, generation=row.generation)
        elif row.generation != old.generation:
            _audit("risk_campaign.membership_reset", request, row.campaign_id, generation=row.generation)
    for campaign_id, old in before.items():
        if old.active and campaign_id not in memberships:
            _audit("risk_campaign.membership_retired", request, campaign_id, generation=old.generation)
    return _campaigns(request, source)


def poll_campaign_reconciliation() -> None:
    foreground_activity.defer_until_idle()
    try:
        reconcile_pending_campaigns()
    except Exception:  # broad-except: A queue read failure must not stop unrelated maintenance; the next poll retries.
        _logger.warning("Campaign evidence reconciliation poll deferred")


def verification_membership(request: Any, campaign_id: str, source: dict[str, Any]) -> CampaignWorkflow:
    """Seed only missing workflow evidence on a verification write, never a GET."""
    from fastapi import HTTPException

    from agent_bom.api.routes.campaigns import _tenant

    tenant_id = _tenant(request)
    store = get_campaign_store()
    stored = store.get(tenant_id, campaign_id)
    if stored is None:
        # Preserve historical membership for comparison when findings vanish.
        # Complete-source and revision fences remain owned by reconciliation.
        _reconcile_campaigns(request, source)
        stored = store.get(tenant_id, campaign_id)
    if stored is None or not stored.member_ids:
        raise HTTPException(status_code=404, detail="Campaign membership evidence was not found for this tenant.")
    return stored
