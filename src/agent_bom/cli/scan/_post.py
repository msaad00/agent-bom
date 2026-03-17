"""Steps 6–9: integrations, SIEM, exit codes."""

from __future__ import annotations

from typing import Any

from agent_bom.cli._common import SEVERITY_ORDER
from agent_bom.cli.scan._context import ScanContext
from agent_bom.output import to_json


def run_integrations(
    ctx: ScanContext,
    *,
    quiet: bool,
    jira_url: Any,
    jira_user: Any,
    jira_token: Any,
    jira_project: Any,
    slack_webhook: Any,
    jira_discover: bool,
    servicenow_flag: bool,
    servicenow_instance: Any,
    servicenow_user: Any,
    servicenow_password: Any,
    slack_discover: bool,
    slack_bot_token: Any,
    vanta_token: Any,
    drata_token: Any,
    siem_type: Any,
    siem_url: Any,
    siem_token: Any,
    siem_index: Any,
    siem_format: str,
    clickhouse_url: Any,
    policy: Any = None,
    **kwargs: Any,
) -> None:
    """Step 8: enterprise integrations (Slack, Jira, Vanta, Drata, SIEM, ClickHouse)."""
    con = ctx.con
    blast_radii = ctx.blast_radii

    # Step 7b: Policy evaluation
    if policy and blast_radii:
        from agent_bom.policy import evaluate_policy, load_policy

        try:
            policy_data = load_policy(policy)
            from agent_bom.output import print_policy_results

            policy_result = evaluate_policy(policy_data, blast_radii)
            print_policy_results(policy_result)
            ctx.policy_passed = policy_result["passed"]

            jira_viol = policy_result.get("jira_violations", [])
            if jira_viol and jira_url and jira_token and jira_project:
                from agent_bom.policy import fire_policy_jira_actions

                n = fire_policy_jira_actions(
                    policy_result=policy_result,
                    jira_url=jira_url,
                    email=jira_user or "",
                    api_token=jira_token,
                    project_key=jira_project,
                )
                if n:
                    con.print(f"  [green]✓[/green] Policy: created {n} Jira ticket(s) for policy violations")
            elif jira_viol and not (jira_url and jira_token and jira_project):
                con.print(
                    f"  [yellow]⚠[/yellow]  Policy: {len(jira_viol)} rule(s) have action='jira' but "
                    "--jira-url/--jira-token/--jira-project are not set"
                )
        except (FileNotFoundError, ValueError) as e:
            import sys

            con.print(f"\n  [red]Policy error: {e}[/red]")
            sys.exit(1)

    # Step 7c: ClickHouse analytics (optional, post-scan)
    if clickhouse_url and blast_radii:
        try:
            import uuid as _uuid_ch

            from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

            _ch_store = ClickHouseAnalyticsStore(url=clickhouse_url)
            _scan_id = str(_uuid_ch.uuid4())
            vuln_dicts = [
                {
                    "package": br.package.name,
                    "version": br.package.version,
                    "ecosystem": br.package.ecosystem,
                    "cve_id": br.vulnerability.id,
                    "cvss_score": getattr(br.vulnerability, "cvss_score", 0.0) or 0.0,
                    "epss_score": getattr(br.vulnerability, "epss_score", 0.0) or 0.0,
                    "severity": br.vulnerability.severity.value.lower(),
                    "source": getattr(br.vulnerability, "source", "osv"),
                    "cmmc_tags": list(br.cmmc_tags) if br.cmmc_tags else [],
                }
                for br in blast_radii
            ]
            for agent in ctx.agents:
                _ch_store.record_scan(_scan_id, agent.name, vuln_dicts)
            if ctx.report:
                _rpt = ctx.report
                _ch_store.record_scan_metadata(
                    {
                        "scan_id": _scan_id,
                        "agent_count": _rpt.total_agents,
                        "package_count": _rpt.total_packages,
                        "vuln_count": _rpt.total_vulnerabilities,
                        "critical_count": len(_rpt.critical_vulns),
                        "high_count": sum(1 for br in _rpt.blast_radii if br.vulnerability.severity.value.lower() == "high"),
                        "posture_grade": "",
                        "scan_duration_ms": 0,
                        "source": "cli",
                        "aisvs_score": float((_rpt.aisvs_benchmark_data or {}).get("overall_score", 0.0)),
                        "has_runtime_correlation": bool(_rpt.runtime_correlation),
                    }
                )
            if not quiet:
                con.print(f"  [green]✓[/green] Analytics: {len(vuln_dicts)} finding(s) recorded to ClickHouse")
        except Exception as _ch_exc:
            if not quiet:
                con.print(f"  [yellow]⚠[/yellow] ClickHouse analytics: {_ch_exc}")

    # Step 8: Enterprise integrations (optional, post-scan)
    if blast_radii and (slack_webhook or jira_url or vanta_token or drata_token):
        import asyncio as _asyncio_int

        findings = []
        for br in blast_radii:
            findings.append(
                {
                    "vulnerability_id": br.vulnerability.id,
                    "severity": br.vulnerability.severity.value.lower(),
                    "package": f"{br.package.name}@{br.package.version}",
                    "risk_score": br.risk_score,
                    "affected_agents": [a.name for a in br.affected_agents] if br.affected_agents else [],
                    "affected_servers": [s.name for s in br.affected_servers] if br.affected_servers else [],
                    "exposed_credentials": list(br.exposed_credentials) if br.exposed_credentials else [],
                    "fixed_version": br.vulnerability.fixed_version,
                    "owasp_tags": list(br.owasp_tags) if br.owasp_tags else [],
                    "owasp_mcp_tags": list(br.owasp_mcp_tags) if br.owasp_mcp_tags else [],
                    "atlas_tags": list(br.atlas_tags) if br.atlas_tags else [],
                    "nist_ai_rmf_tags": list(br.nist_ai_rmf_tags) if br.nist_ai_rmf_tags else [],
                }
            )

        if slack_webhook and findings:
            try:
                from agent_bom.integrations.slack import build_summary_message, send_slack_alert, send_slack_payload

                async def _send_slack():
                    for f in findings[:10]:
                        await send_slack_alert(slack_webhook, f)
                    if len(findings) > 1:
                        summary = build_summary_message(findings)
                        await send_slack_payload(slack_webhook, summary)

                _asyncio_int.run(_send_slack())
                con.print(f"  [green]✓[/green] Slack: sent {min(len(findings), 10)} alert(s)")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Slack alert failed: {exc}")

        if jira_url and jira_token and jira_project and findings:
            try:
                from agent_bom.integrations.jira import create_jira_ticket

                async def _create_jira():
                    created = 0
                    for f in findings[:20]:
                        await create_jira_ticket(jira_url, jira_user or "", jira_token, jira_project, f)
                        created += 1
                    return created

                jira_count = _asyncio_int.run(_create_jira())
                con.print(f"  [green]✓[/green] Jira: created {jira_count} ticket(s)")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Jira ticket creation failed: {exc}")

        if vanta_token and findings:
            try:
                from agent_bom.integrations.vanta import upload_evidence

                _asyncio_int.run(upload_evidence(vanta_token, findings))  # type: ignore[arg-type]
                con.print("  [green]✓[/green] Vanta: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Vanta upload failed: {exc}")

        if drata_token and findings:
            try:
                from agent_bom.integrations.drata import upload_evidence as upload_evidence_drata

                _asyncio_int.run(upload_evidence_drata(drata_token, findings))  # type: ignore[arg-type]
                con.print("  [green]✓[/green] Drata: evidence uploaded")
            except Exception as exc:
                con.print(f"  [yellow]⚠[/yellow] Drata upload failed: {exc}")

    # SIEM push
    if siem_type and siem_url and blast_radii:
        try:
            from agent_bom.siem import SIEMConfig, create_connector, format_event

            siem_config = SIEMConfig(
                name=siem_type,
                url=siem_url,
                token=siem_token or "",
                index=siem_index or "agent-bom-alerts",
            )
            connector = create_connector(siem_type, siem_config)

            events: list[dict] = []
            for br in blast_radii:
                raw = {
                    "type": "scan_alert",
                    "severity": br.vulnerability.severity.value,
                    "message": f"{br.vulnerability.id} in {br.package.name}@{br.package.version}",
                    "vulnerability_id": br.vulnerability.id,
                    "package": br.package.name,
                    "version": br.package.version,
                    "ecosystem": br.package.ecosystem,
                    "is_kev": br.vulnerability.is_kev,
                    "affected_agents": [a.name for a in br.affected_agents],
                    "exposed_credentials": br.exposed_credentials,
                    "atlas_tags": getattr(br, "atlas_tags", []),
                    "attack_tags": getattr(br, "attack_tags", []),
                    "owasp_tags": getattr(br, "owasp_tags", []),
                }
                events.append(format_event(raw, siem_format))

            sent = connector.send_batch(events)
            con.print(f"  [green]✓[/green] SIEM ({siem_type}): pushed {sent}/{len(events)} event(s)")
        except Exception as exc:
            con.print(f"  [yellow]⚠[/yellow] SIEM push failed: {exc}")
    elif siem_type and not siem_url:
        con.print(f"  [yellow]⚠[/yellow] --siem {siem_type} set but --siem-url is required")


def compute_exit_code(
    ctx: ScanContext,
    *,
    fail_on_severity: Any,
    warn_on_severity: Any,
    fail_on_kev: bool,
    fail_if_ai_risk: bool,
    push_url: Any,
    push_api_key: Any,
    quiet: bool,
    **kwargs: Any,
) -> int:
    """Step 9: compute final exit code based on policy flags."""
    con = ctx.con
    blast_radii = ctx.blast_radii
    report = ctx.report

    exit_code = 0

    # Filter blast radii to exclude VEX-suppressed vulnerabilities
    from agent_bom.vex import is_vex_suppressed as _is_vex_suppressed

    _active_blast_radii = [br for br in blast_radii if not _is_vex_suppressed(br.vulnerability)]

    # Delta mode: further restrict active findings to new-only
    if ctx.delta_result is not None:
        _new_keys = {(d.get("vulnerability_id", "").upper(), d.get("package", "")) for d in ctx.delta_result.new_items}
        _active_blast_radii = [
            br for br in _active_blast_radii if (br.vulnerability.id.upper(), f"{br.package.name}@{br.package.version}") in _new_keys
        ]

    if fail_on_severity and _active_blast_radii:
        threshold = SEVERITY_ORDER.get(fail_on_severity, 0)
        for br in _active_blast_radii:
            sev = br.vulnerability.severity.value.lower()
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                if not quiet:
                    con.print(f"\n  [red]Exiting with code 1: found {sev} vulnerability ({br.vulnerability.id})[/red]")
                exit_code = 1
                break

    # IaC findings also respect --fail-on-severity
    if fail_on_severity and exit_code == 0 and report and report.iac_findings_data:
        threshold = SEVERITY_ORDER.get(fail_on_severity, 0)
        for f in report.iac_findings_data.get("findings", []):
            sev = (f.get("severity") or "medium").lower()
            if SEVERITY_ORDER.get(sev, 0) >= threshold:
                if not quiet:
                    con.print(
                        f"\n  [red]Exiting with code 1: IaC {sev} misconfiguration"
                        f" ({f.get('rule_id', '?')} in {f.get('file_path', '?')})[/red]"
                    )
                exit_code = 1
                break

    # Two-tier: warn-on threshold (exit 0 with banner)
    if warn_on_severity and _active_blast_radii and exit_code == 0:
        warn_threshold = SEVERITY_ORDER.get(warn_on_severity.lower(), 0)
        warn_matches = [
            br for br in _active_blast_radii if SEVERITY_ORDER.get(br.vulnerability.severity.value.lower(), 0) >= warn_threshold
        ]
        if warn_matches:
            if not quiet:
                con.print(
                    f"\n  [yellow]⚠[/yellow]  {len(warn_matches)} finding(s) at or above "
                    f"{warn_on_severity.upper()} severity (--warn-on threshold). "
                    f"Upgrade to --fail-on-severity to enforce."
                )

    if fail_on_kev and _active_blast_radii:
        kev_findings = [br for br in _active_blast_radii if br.vulnerability.is_kev]
        if kev_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(kev_findings)} CISA KEV "
                    f"finding(s) found (use --enrich if not already)[/red bold]"
                )
            exit_code = 1

    if fail_if_ai_risk and _active_blast_radii:
        ai_findings = [br for br in _active_blast_radii if br.ai_risk_context and br.exposed_credentials]
        if ai_findings:
            if not quiet:
                con.print(
                    f"\n  [red bold]Exiting with code 1: {len(ai_findings)} AI framework "
                    f"package(s) with vulnerabilities and exposed credentials[/red bold]"
                )
            exit_code = 1

    if not ctx.policy_passed:
        exit_code = 1

    # Push results to central dashboard
    if push_url and report:
        try:
            from agent_bom.push import push_results as _push

            report_data = to_json(report)
            ok = _push(push_url, report_data, api_key=push_api_key)
            if ok and not quiet:
                con.print(f"\n  [green]Results pushed to {push_url}[/green]")
            elif not ok and not quiet:
                con.print(f"\n  [yellow]Push to {push_url} failed[/yellow]")
        except Exception as push_err:
            if not quiet:
                con.print(f"\n  [yellow]Push failed: {push_err}[/yellow]")

    ctx.exit_code = exit_code
    return exit_code
