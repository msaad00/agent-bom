"""Regression tests for audit-queue fixes (malicious stream, COUNT cache, SCIM keys, no-auth role)."""

from __future__ import annotations

from agent_bom.api.auth import KeyStore, Role, create_api_key_record, get_key_store, set_key_store
from agent_bom.api.findings_count_cache import (
    approximate_total_threshold,
    cache_key,
    reset_findings_count_cache,
    resolve_effective_approximate_total,
    set_cached_total,
)
from agent_bom.api.scim import revoke_credentials_for_scim_user
from agent_bom.finding import _forward_fixed_version, blast_radius_to_finding
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.output.console_render import build_remediation_plan
from agent_bom.rbac import Role as RbacRole
from agent_bom.rbac import _no_auth_role


def _malicious_blast_radius():
    from agent_bom.models import BlastRadius

    pkg = Package(
        name="flatmap-stream",
        version="0.1.1",
        ecosystem="npm",
        is_malicious=True,
        malicious_reason="MAL-2024-1",
    )
    vuln = Vulnerability(id="MAL-2024-1", summary="malware", severity=Severity.MEDIUM)
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        risk_score=5.0,
    )


def test_unified_finding_carries_malicious_fields() -> None:
    finding = blast_radius_to_finding(_malicious_blast_radius())
    payload = finding.to_dict()
    assert payload["is_malicious"] is True
    assert payload["malicious_reason"] == "MAL-2024-1"
    assert "remove" in (payload["remediation_guidance"] or "").lower()


def test_remediation_plan_remove_command_for_malicious_package() -> None:
    plan = build_remediation_plan([_malicious_blast_radius()])
    assert plan
    assert plan[0]["is_malicious"] is True
    assert "Remove" in plan[0]["action"]
    assert plan[0]["command"] == "npm uninstall flatmap-stream"


def test_remediation_console_renders_remove_not_monitor_for_malicious() -> None:
    """Console remediation plan must render an explicit REMOVE + MALICIOUS marker
    for a known-malicious package, never bucket it under 'monitor upstream for
    patches' (which is only correct for no-fix-yet CVEs)."""
    import io

    from rich.console import Console

    from agent_bom import output as output_mod
    from agent_bom.models import AIBOMReport
    from agent_bom.output.console_render import print_remediation_plan

    report = AIBOMReport(blast_radii=[_malicious_blast_radius()])

    buffer = io.StringIO()
    original = output_mod.console
    output_mod.console = Console(file=buffer, force_terminal=False, width=200, no_color=True)
    try:
        print_remediation_plan(report)
    finally:
        output_mod.console = original

    text = buffer.getvalue()
    assert "flatmap-stream" in text
    assert "monitor upstream for patches" not in text
    assert "MALICIOUS" in text
    assert "Remove" in text


def test_scan_exits_one_on_malicious_package_by_default() -> None:
    """A known-malicious package must fail the scan (exit 1) even without the
    opt-in --fail-on-malicious flag, matching `check`'s fail-closed policy. A
    default scan silently exiting 0 would let a malicious dependency through."""
    from io import StringIO

    from rich.console import Console

    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import compute_exit_code

    ctx = ScanContext(
        con=Console(file=StringIO(), force_terminal=False),
        blast_radii=[_malicious_blast_radius()],
    )
    code = compute_exit_code(
        ctx,
        fail_on_severity=None,
        warn_on_severity=None,
        fail_on_kev=False,
        fail_if_ai_risk=False,
        push_url=None,
        push_api_key=None,
        quiet=True,
        fail_on_malicious=False,
    )
    assert code == 1


def test_forward_fixed_version_rejects_downgrade() -> None:
    assert _forward_fixed_version("0.2.1", "1.2.0", "npm") is None
    assert _forward_fixed_version("1.2.3", "1.2.0", "npm") == "1.2.3"


def test_resolve_effective_approximate_total_uses_cached_threshold(monkeypatch) -> None:
    reset_findings_count_cache()
    monkeypatch.setattr("agent_bom.config.FINDINGS_APPROXIMATE_TOTAL_THRESHOLD", 1000)
    key = cache_key(tenant_id="t1", severity=None, scan_id=None, origin="bulk_ingest")
    set_cached_total(key, 50_000)
    assert resolve_effective_approximate_total(requested=False, tenant_id="t1", severity=None, scan_id=None) is True
    assert approximate_total_threshold() == 1000


def test_scim_revoke_matches_scim_subject_id(monkeypatch) -> None:
    store = KeyStore()
    original = get_key_store()
    set_key_store(store)
    monkeypatch.setattr("agent_bom.api.auth.get_key_store", lambda: store)
    try:
        bound = create_api_key_record(
            "abom_test_bound_key_123456789012",
            name="ci-pipeline-token",
            role=Role.VIEWER,
            tenant_id="default",
            scim_subject_id="user-abc",
        )
        legacy = create_api_key_record(
            "abom_test_legacy_key_123456789012",
            name="user-abc",
            role=Role.VIEWER,
            tenant_id="default",
        )
        store.add(bound)
        store.add(legacy)

        class _User:
            user_id = "user-abc"
            user_name = "alice@example.com"
            external_id = None

        revoked = revoke_credentials_for_scim_user("default", _User())
        assert revoked == 2
        assert bound.is_revoked()
        assert legacy.is_revoked()
    finally:
        set_key_store(original)


def test_no_auth_role_defaults_to_admin_for_local_compatibility(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", False)
    monkeypatch.setattr("agent_bom.config.NO_AUTH_ROLE", "admin")
    assert _no_auth_role() is RbacRole.ADMIN


def test_demo_estate_clamps_no_auth_to_viewer(monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", True)
    monkeypatch.setattr("agent_bom.config.NO_AUTH_ROLE", "admin")
    assert _no_auth_role() is RbacRole.VIEWER
