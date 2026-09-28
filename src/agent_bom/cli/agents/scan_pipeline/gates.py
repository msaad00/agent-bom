"""Stage 12: integrations and the exit-code verdict."""

from __future__ import annotations

import sys

from agent_bom.cli.agents._output import render_output
from agent_bom.cli.agents._post import compute_exit_code, run_integrations
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState


def _run_integrations(opts: ScanOptions, st: ScanState) -> None:
    # Step 8: Enterprise integrations + SIEM + policy (post-scan)
    run_integrations(
        st.ctx,
        quiet=opts.quiet,
        jira_url=opts.jira_url,
        jira_user=opts.jira_user,
        jira_token=opts.jira_token,
        jira_project=opts.jira_project,
        slack_webhook=opts.slack_webhook,
        jira_discover=opts.jira_discover,
        servicenow_flag=opts.servicenow_flag,
        servicenow_instance=opts.servicenow_instance,
        servicenow_token=opts.servicenow_token,
        slack_discover=opts.slack_discover,
        slack_bot_token=opts.slack_bot_token,
        vanta_token=opts.vanta_token,
        drata_token=opts.drata_token,
        siem_type=opts.siem_type,
        siem_url=opts.siem_url,
        siem_token=opts.siem_token,
        siem_index=opts.siem_index,
        siem_format=opts.siem_format,
        clickhouse_url=opts.clickhouse_url,
        policy=opts.policy,
    )


def _compute_exit(opts: ScanOptions, st: ScanState) -> None:
    # Step 9: Exit code
    from agent_bom.enrichment_posture import describe_enrichment_posture

    st.ctx.enrichment_posture = describe_enrichment_posture()
    exit_code = compute_exit_code(
        st.ctx,
        fail_on_severity=opts.fail_on_severity,
        warn_on_severity=opts.warn_on_severity,
        fail_on_kev=opts.fail_on_kev,
        fail_on_malicious=opts.fail_on_malicious,
        fail_if_ai_risk=opts.fail_if_ai_risk,
        push_url=opts.push_url,
        push_api_key=opts.push_api_key,
        # Structured renderers own stdout only when no output file is selected.
        # Their non-zero verdict is carried by the process status and report
        # fields; human gate explanations after the document would make the
        # JSON/SARIF stream invalid. File output keeps the console explanation.
        quiet=opts.quiet or (opts.output_format != "console" and opts.output in {None, "-"}),
    )

    if opts.agent_mode:
        render_output(
            st.ctx,
            output=opts.output,
            output_format=opts.output_format,
            no_tree=opts.no_tree,
            quiet=opts.quiet,
            no_color=opts.no_color,
            open_report=opts.open_report,
            offline_html=opts.offline_html,
            compliance_export=opts.compliance_export,
            mermaid_mode=opts.mermaid_mode,
            push_gateway=opts.push_gateway,
            otel_endpoint=opts.otel_endpoint,
            baseline=opts.baseline,
            delta_mode=opts.delta_mode,
            verbose=opts.verbose,
            exclude_unfixable=opts.exclude_unfixable,
            fixable_only=opts.fixable_only,
            agent_mode=opts.agent_mode,
            agent_token_budget=opts.agent_token_budget,
            agent_mode_full=opts.agent_mode_full,
            page=opts.page,
        )

    if exit_code:
        sys.exit(exit_code)


def run_gates(opts: ScanOptions, st: ScanState) -> None:
    """Post-scan integrations and the exit-code verdict."""
    _run_integrations(opts, st)
    _compute_exit(opts, st)
