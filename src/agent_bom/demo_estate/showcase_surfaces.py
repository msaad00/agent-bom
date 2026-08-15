"""Seed synthetic evidence into auxiliary stores the demo UI reads directly.

The showcase graph and scan job do not populate the Skills, CWPP lifecycle, or
campaign-verification stores.  This module writes small, explicitly synthetic
records through those stores' public contracts so the demo journey reaches the
real product surfaces without inventing alternate APIs or implying live-cloud
proof.  Every seeder is tenant-scoped, idempotent, and refuses to mix demo rows
into operator-owned state.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, cast

_DEMO_SKILLS_RUN_ID = "synthetic-demo-skills-v1"
_DEMO_CAMPAIGN_ID = "synthetic-demo-campaign-verification"
_DEMO_CWPP_ACCOUNT_PREFIX = "synthetic-demo-"


def seed_showcase_auxiliary_surfaces(*, tenant_id: str) -> dict[str, int]:
    """Seed the three otherwise-empty demo stores through their public APIs."""
    return {
        "skills_scans": _seed_skills_scan(tenant_id=tenant_id),
        "cwpp_executions": _seed_cwpp_executions(tenant_id=tenant_id),
        "verification_queue": _seed_verification_queue(tenant_id=tenant_id),
    }


def _seed_skills_scan(*, tenant_id: str) -> int:
    from agent_bom.api.skills_scan_store import SkillsScanRun, get_skills_scan_store

    store = get_skills_scan_store()
    existing = store.list_for_tenant(tenant_id, limit=100)
    if any(run.run_id != _DEMO_SKILLS_RUN_ID for run in existing):
        return 0
    if any(run.run_id == _DEMO_SKILLS_RUN_ID for run in existing):
        return 0

    created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    files = [
        _skill_file(
            path="synthetic-demo/skills/repository-review/SKILL.md",
            status="clean",
            content="benign",
            review="clean",
            provenance="verified",
            signer="synthetic-demo@example.invalid",
        ),
        _skill_file(
            path="synthetic-demo/skills/deployment-helper/SKILL.md",
            status="suspicious",
            content="suspicious",
            review="high_risk",
            provenance="unsigned",
            credential_env_vars=["DEPLOYMENT_TOKEN"],
            finding={
                "severity": "high",
                "category": "credential_access",
                "title": "Broad credential reference requires review",
                "detail": "Synthetic demo instruction references a deployment credential without a declared scope.",
                "recommendation": "Bind the credential to the minimum deployment scope and require approval.",
                "confidence": "high",
            },
        ),
        _skill_file(
            path="synthetic-demo/skills/incident-summary/SKILL.md",
            status="pending",
            content="benign",
            review="review",
            provenance="unsigned",
        ),
    ]
    payload: dict[str, Any] = {
        "$schema": "https://agent-bom.github.io/schemas/skills-scan/v1",
        "schema_version": "1",
        "scan_type": "skills",
        "report_type": "skills_scan",
        "status": "completed",
        "run_id": _DEMO_SKILLS_RUN_ID,
        "created_at": created_at,
        "generated_at": created_at,
        "synthetic": True,
        "note": "Explicitly synthetic skill evidence for the bundled enterprise demo.",
        "summary": {
            "files_scanned": len(files),
            "bundles": len(files),
            "bundled_files": len(files),
            "packages_found": 0,
            "servers_found": 0,
            "credential_env_vars": 1,
            "findings": 1,
            "verified_files": 1,
            "suspicious_files": 1,
            "malicious_files": 0,
            "blocked_files": 0,
            "high_risk_files": 1,
            "clean_files": 1,
            "suspicious_status_files": 1,
            "malicious_status_files": 0,
            "pending_status_files": 1,
            "unavailable_status_files": 0,
        },
        "files": files,
    }
    store.put(
        SkillsScanRun(
            tenant_id=tenant_id,
            run_id=_DEMO_SKILLS_RUN_ID,
            created_at=created_at,
            payload=payload,
        )
    )
    return 1


def _skill_file(
    *,
    path: str,
    status: str,
    content: str,
    review: str,
    provenance: str,
    signer: str | None = None,
    credential_env_vars: list[str] | None = None,
    finding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = [finding] if finding else []
    return {
        "path": path,
        "status": status,
        "synthetic": True,
        "bundle": {"stable_id": path, "files": [{"path": path}]},
        "packages": [],
        "servers": [],
        "credential_env_vars": credential_env_vars or [],
        "audit": {
            "passed": not findings,
            "packages_checked": 0,
            "servers_checked": 0,
            "credentials_checked": len(credential_env_vars or []),
            "behavioral_summary": "Explicitly synthetic enterprise-demo instruction evidence.",
            "findings": findings,
        },
        "trust": {
            "verdict": content,
            "content_verdict": content,
            "provenance_verdict": "verified" if provenance == "verified" else "unverified",
            "review_verdict": review,
            "confidence": "high",
            "recommendations": [],
            "review_reasons": [],
        },
        "provenance": {
            "status": provenance,
            "reason": "synthetic_demo_fixture",
            "sha256": None,
            "signer": signer,
            "has_sigstore_bundle": provenance == "verified",
        },
        "threat_intel": None,
    }


def _seed_cwpp_executions(*, tenant_id: str) -> int:
    from agent_bom.cloud.side_scan_lifecycle import (
        CleanupStatus,
        ExecutionStatus,
        SideScanProvider,
        get_side_scan_state_store,
        new_side_scan_execution,
    )

    store = get_side_scan_state_store()
    existing = store.list_recent(tenant_id=tenant_id, limit=200)
    if any(not record.account_id.startswith(_DEMO_CWPP_ACCOUNT_PREFIX) for record in existing):
        return 0
    if existing:
        return 0

    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    specs = (
        ("aws", "workload-payments", ExecutionStatus.SCAN_COMPLETE, CleanupStatus.COMPLETE, 182, 7, 1, ""),
        ("azure", "workload-clinical", ExecutionStatus.PARTIAL, CleanupStatus.COMPLETE, 96, 3, 0, "synthetic_partial_collection"),
        ("gcp", "workload-analytics", ExecutionStatus.DENIED, CleanupStatus.NOT_STARTED, 0, 0, 0, "synthetic_scope_denied"),
    )
    for provider, target, terminal, cleanup, packages, vulnerabilities, secrets, failure_code in specs:
        record = new_side_scan_execution(
            tenant_id=tenant_id,
            provider=cast(SideScanProvider, provider),
            account_id=f"{_DEMO_CWPP_ACCOUNT_PREFIX}{provider}",
            target_id=f"synthetic://{provider}/disks/{target}",
            collector_id=f"synthetic-demo-{provider}-collector",
            idempotency_key=f"synthetic-demo-{provider}-v1",
            now=now,
        )
        current = store.create_or_get(record)
        if terminal is ExecutionStatus.DENIED:
            final = current.transition(
                status=terminal,
                phase="finished",
                cleanup_status=cleanup,
                failure_code=failure_code,
                warning_codes=("synthetic_demo_evidence",),
                now=now,
            )
            store.save(final, expected_version=current.state_version)
            continue
        running = current.transition(status=ExecutionStatus.RUNNING, phase="scanning", now=now)
        store.save(running, expected_version=current.state_version)
        final = running.transition(
            status=terminal,
            phase="finished",
            cleanup_status=cleanup,
            package_count=packages,
            vulnerability_count=vulnerabilities,
            secret_count=secrets,
            config_finding_count=2 if packages else 0,
            failure_code=failure_code,
            warning_codes=("synthetic_demo_evidence",),
            now=now,
        )
        store.save(final, expected_version=running.state_version)
    return len(specs)


def _seed_verification_queue(*, tenant_id: str) -> int:
    from agent_bom.api.campaign_store import get_campaign_store

    store = get_campaign_store()
    existing = store.list(tenant_id)
    if any(row.campaign_id != _DEMO_CAMPAIGN_ID for row in existing):
        return 0
    if any(row.campaign_id == _DEMO_CAMPAIGN_ID for row in existing):
        return 0

    rows = store.reconcile_memberships(
        tenant_id,
        {
            _DEMO_CAMPAIGN_ID: (
                "synthetic-demo-membership-v1",
                ("synthetic-finding-mcp-egress", "synthetic-finding-exposed-credential"),
                "Synthetic demo: verify the contained MCP-to-model-egress path",
            )
        },
        complete=True,
    )
    row = rows[0]
    due = (datetime.now(timezone.utc) + timedelta(days=7)).replace(microsecond=0).isoformat()
    updated = store.patch(
        tenant_id,
        _DEMO_CAMPAIGN_ID,
        expected_version=row.version,
        fields={"owner": "platform-security@example.invalid", "sla_due_at": due},
    )
    if updated is None:  # pragma: no cover - isolated seeder owns this version
        return 0
    # A campaign enters the verification queue when the finding source no longer
    # returns it but the original membership remains available for re-checking.
    store.reconcile_memberships(tenant_id, {}, complete=True)
    return 1


__all__ = ["seed_showcase_auxiliary_surfaces"]
