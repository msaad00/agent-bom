"""HTML report generator for AI-BOM scans.

Split into cohesive submodules (see #1522); this package re-exports the
original public and semi-public symbols so ``agent_bom.output.html.X`` keeps
working unchanged.
"""
from __future__ import annotations

from agent_bom.output.html._common import (
    _PAGE_SIZE,
    _PKG_PREVIEW,
    _SEV_COLOR,
    _esc,
    _sev_badge,
)
from agent_bom.output.html.document import export_html, to_html
from agent_bom.output.html.scripts import (
    _EXTERNAL_SCRIPT_TAGS,
    SCALE_REPORT_SCRIPT,
    _apply_offline_assets_mode,
    _offline_assets_notice,
    _offline_assets_script,
    render_graph_script,
)
from agent_bom.output.html.sections import (
    _ai_inventory_section,
    _attack_flow_elements,
    _attack_flow_section,
    _blast_table,
    _chart_data,
    _cis_benchmark_section,
    _cis_evidence_html,
    _compliance_section,
    _cytoscape_elements,
    _delta_banner,
    _enforcement_section,
    _exposure_path_section,
    _inventory_cards,
    _non_cve_findings,
    _pager_controls,
    _policy_findings_section,
    _remediation_list,
    _skill_audit_section,
    _summary_cards,
    _trust_assessment_section,
    _vuln_table,
    _warn_gate_banner,
)
from agent_bom.output.html.styles import render_styles
from agent_bom.output.html.tabs import _TAB_DEFS, _apply_tabs

__all__ = [
    "to_html",
    "export_html",
]
