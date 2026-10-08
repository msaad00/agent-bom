"""Output formatters for AI-BOM reports."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.badge import (
        export_badge,
        to_badge,
        to_rsp_badge,
    )
    from agent_bom.output.compact import (
        _compact_detail,
        _coverage_bar,
        _iter_cis_bundles,
        _pct,
        _posture_grade_badge,
        print_compact_agents,
        print_compact_blast_radius,
        print_compact_cis_posture,
        print_compact_compliance_status,
        print_compact_export_hint,
        print_compact_graph_findings,
        print_compact_remediation,
        print_compact_summary,
    )
    from agent_bom.output.compliance_export import (
        export_compliance_bundle,
    )
    from agent_bom.output.console_render import (
        SEVERITY_BADGES,
        SEVERITY_TEXT,
        _sev_badge,
        build_remediation_plan,
        console,
        print_agent_tree,
        print_attack_flow_tree,
        print_blast_radius,
        print_diff,
        print_export_hint,
        print_policy_results,
        print_posture_summary,
        print_remediation_plan,
        print_scan_performance_summary,
        print_severity_chart,
        print_summary,
        print_threat_frameworks,
    )
    from agent_bom.output.csv_fmt import (
        export_csv,
        to_csv,
    )
    from agent_bom.output.cyclonedx_fmt import (
        export_cyclonedx,
        to_cyclonedx,
    )
    from agent_bom.output.iceberg_catalog import (
        IcebergCatalogConfig,
        maybe_register_iceberg,
    )
    from agent_bom.output.iceberg_catalog import (
        register_findings as register_iceberg_findings,
    )
    from agent_bom.output.json_fmt import (
        _build_framework_summary,
        _build_remediation_json,
        _risk_narrative,
        export_json,
        redact_json_payload,
        to_json,
        to_redacted_json,
    )
    from agent_bom.output.junit import (
        export_junit,
        to_junit,
    )
    from agent_bom.output.markdown import (
        export_markdown,
        to_markdown,
    )
    from agent_bom.output.parquet_fmt import (
        export_parquet,
        to_arrow_table,
        to_parquet_bytes,
    )
    from agent_bom.output.sarif import (
        export_sarif,
        to_sarif,
    )
    from agent_bom.output.spdx2_fmt import (
        export_spdx2,
        export_spdx2_tagvalue,
        to_spdx2,
        to_spdx2_tagvalue,
    )
    from agent_bom.output.spdx_fmt import (
        export_spdx,
        to_spdx,
    )

# Each format lives in its own module and is re-exported here for backward
# compatibility. The formatters pull in compliance, SBOM, and HTTP stacks, so
# they resolve on first access (PEP 562) instead of on every CLI start.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "export_badge": ("agent_bom.output.badge", "export_badge"),
    "to_badge": ("agent_bom.output.badge", "to_badge"),
    "to_rsp_badge": ("agent_bom.output.badge", "to_rsp_badge"),
    "export_compliance_bundle": ("agent_bom.output.compliance_export", "export_compliance_bundle"),
    "SEVERITY_BADGES": ("agent_bom.output.console_render", "SEVERITY_BADGES"),
    "SEVERITY_TEXT": ("agent_bom.output.console_render", "SEVERITY_TEXT"),
    "_sev_badge": ("agent_bom.output.console_render", "_sev_badge"),
    "build_remediation_plan": ("agent_bom.output.console_render", "build_remediation_plan"),
    "console": ("agent_bom.output.console_render", "console"),
    "print_agent_tree": ("agent_bom.output.console_render", "print_agent_tree"),
    "print_attack_flow_tree": ("agent_bom.output.console_render", "print_attack_flow_tree"),
    "print_blast_radius": ("agent_bom.output.console_render", "print_blast_radius"),
    "print_diff": ("agent_bom.output.console_render", "print_diff"),
    "print_export_hint": ("agent_bom.output.console_render", "print_export_hint"),
    "print_policy_results": ("agent_bom.output.console_render", "print_policy_results"),
    "print_posture_summary": ("agent_bom.output.console_render", "print_posture_summary"),
    "print_remediation_plan": ("agent_bom.output.console_render", "print_remediation_plan"),
    "print_scan_performance_summary": ("agent_bom.output.console_render", "print_scan_performance_summary"),
    "print_severity_chart": ("agent_bom.output.console_render", "print_severity_chart"),
    "print_summary": ("agent_bom.output.console_render", "print_summary"),
    "print_threat_frameworks": ("agent_bom.output.console_render", "print_threat_frameworks"),
    "export_csv": ("agent_bom.output.csv_fmt", "export_csv"),
    "to_csv": ("agent_bom.output.csv_fmt", "to_csv"),
    "export_cyclonedx": ("agent_bom.output.cyclonedx_fmt", "export_cyclonedx"),
    "to_cyclonedx": ("agent_bom.output.cyclonedx_fmt", "to_cyclonedx"),
    "IcebergCatalogConfig": ("agent_bom.output.iceberg_catalog", "IcebergCatalogConfig"),
    "maybe_register_iceberg": ("agent_bom.output.iceberg_catalog", "maybe_register_iceberg"),
    "register_iceberg_findings": ("agent_bom.output.iceberg_catalog", "register_findings"),
    "_build_framework_summary": ("agent_bom.output.json_fmt", "_build_framework_summary"),
    "_build_remediation_json": ("agent_bom.output.json_fmt", "_build_remediation_json"),
    "_risk_narrative": ("agent_bom.output.json_fmt", "_risk_narrative"),
    "export_json": ("agent_bom.output.json_fmt", "export_json"),
    "redact_json_payload": ("agent_bom.output.json_fmt", "redact_json_payload"),
    "to_json": ("agent_bom.output.json_fmt", "to_json"),
    "to_redacted_json": ("agent_bom.output.json_fmt", "to_redacted_json"),
    "export_junit": ("agent_bom.output.junit", "export_junit"),
    "to_junit": ("agent_bom.output.junit", "to_junit"),
    "export_markdown": ("agent_bom.output.markdown", "export_markdown"),
    "to_markdown": ("agent_bom.output.markdown", "to_markdown"),
    "export_parquet": ("agent_bom.output.parquet_fmt", "export_parquet"),
    "to_arrow_table": ("agent_bom.output.parquet_fmt", "to_arrow_table"),
    "to_parquet_bytes": ("agent_bom.output.parquet_fmt", "to_parquet_bytes"),
    "export_sarif": ("agent_bom.output.sarif", "export_sarif"),
    "to_sarif": ("agent_bom.output.sarif", "to_sarif"),
    "export_spdx2": ("agent_bom.output.spdx2_fmt", "export_spdx2"),
    "export_spdx2_tagvalue": ("agent_bom.output.spdx2_fmt", "export_spdx2_tagvalue"),
    "to_spdx2": ("agent_bom.output.spdx2_fmt", "to_spdx2"),
    "to_spdx2_tagvalue": ("agent_bom.output.spdx2_fmt", "to_spdx2_tagvalue"),
    "export_spdx": ("agent_bom.output.spdx_fmt", "export_spdx"),
    "to_spdx": ("agent_bom.output.spdx_fmt", "to_spdx"),
    "_compact_detail": ("agent_bom.output.compact", "_compact_detail"),
    "_coverage_bar": ("agent_bom.output.compact", "_coverage_bar"),
    "_iter_cis_bundles": ("agent_bom.output.compact", "_iter_cis_bundles"),
    "_pct": ("agent_bom.output.compact", "_pct"),
    "_posture_grade_badge": ("agent_bom.output.compact", "_posture_grade_badge"),
    "print_compact_agents": ("agent_bom.output.compact", "print_compact_agents"),
    "print_compact_blast_radius": ("agent_bom.output.compact", "print_compact_blast_radius"),
    "print_compact_cis_posture": ("agent_bom.output.compact", "print_compact_cis_posture"),
    "print_compact_compliance_status": ("agent_bom.output.compact", "print_compact_compliance_status"),
    "print_compact_export_hint": ("agent_bom.output.compact", "print_compact_export_hint"),
    "print_compact_graph_findings": ("agent_bom.output.compact", "print_compact_graph_findings"),
    "print_compact_remediation": ("agent_bom.output.compact", "print_compact_remediation"),
    "print_compact_summary": ("agent_bom.output.compact", "print_compact_summary"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'agent_bom.output' has no attribute {name!r}")
    value = getattr(import_module(target[0]), target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


# ─── HTML Output (delegated to html.py) ──────────────────────────────────────


def to_html(report: AIBOMReport, blast_radii: list | None = None, *, offline_assets: bool = False) -> str:
    """Generate a self-contained HTML report string."""
    from agent_bom.output.html import to_html as _to_html

    return _to_html(report, blast_radii or [], offline_assets=offline_assets)


def export_html(
    report: AIBOMReport,
    output_path: str,
    blast_radii: list | None = None,
    *,
    offline_assets: bool = False,
) -> None:
    """Export report as a self-contained HTML file."""
    from agent_bom.output.html import export_html as _export_html

    _export_html(report, output_path, blast_radii or [], offline_assets=offline_assets)


def to_pdf(report: AIBOMReport, blast_radii: list | None = None) -> bytes:
    """Generate a PDF report using the optional PDF renderer."""
    from agent_bom.output.pdf import to_pdf as _to_pdf

    return _to_pdf(report, blast_radii or [])


def export_pdf(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Export report as a PDF file using the optional PDF renderer."""
    from agent_bom.output.pdf import export_pdf as _export_pdf

    _export_pdf(report, output_path, blast_radii or [])


# ─── Prometheus Output (delegated to prometheus.py) ──────────────────────────


def to_prometheus(report: AIBOMReport, blast_radii: list | None = None) -> str:
    """Generate Prometheus text exposition format string."""
    from agent_bom.output.prometheus import to_prometheus as _to_prometheus

    return _to_prometheus(report, blast_radii)


def export_prometheus(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Write Prometheus metrics to a .prom file."""
    from agent_bom.output.prometheus import export_prometheus as _export_prometheus

    _export_prometheus(report, output_path, blast_radii)


def push_to_gateway(
    gateway_url: str,
    report: AIBOMReport,
    blast_radii: list | None = None,
    job: str = "agent-bom",
    instance: str | None = None,
) -> None:
    """Push scan metrics to a Prometheus Pushgateway."""
    from agent_bom.output.prometheus import push_to_gateway as _push

    _push(gateway_url, report, blast_radii, job=job, instance=instance)


def push_otlp(
    endpoint: str,
    report: AIBOMReport,
    blast_radii: list | None = None,
) -> None:
    """Export metrics via OpenTelemetry OTLP/HTTP (requires agent-bom[otel])."""
    from agent_bom.output.prometheus import push_otlp as _push_otlp

    _push_otlp(endpoint, report, blast_radii)
