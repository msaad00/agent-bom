"""Output formatters for AI-BOM reports."""

from __future__ import annotations

from agent_bom.models import AIBOMReport

# ─── Delegated format modules ────────────────────────────────────────────────
# Each format lives in its own module; re-exported here for backward compat.
from agent_bom.output.badge import (  # noqa: E402
    export_badge,  # noqa: F401
    to_badge,  # noqa: F401
    to_rsp_badge,  # noqa: F401
)
from agent_bom.output.compliance_export import (  # noqa: E402
    export_compliance_bundle,  # noqa: F401
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
from agent_bom.output.csv_fmt import (  # noqa: E402
    export_csv,  # noqa: F401
    to_csv,  # noqa: F401
)
from agent_bom.output.cyclonedx_fmt import (  # noqa: E402
    export_cyclonedx,  # noqa: F401
    to_cyclonedx,  # noqa: F401
)
from agent_bom.output.json_fmt import (  # noqa: E402
    _build_framework_summary,  # noqa: F401
    _build_remediation_json,  # noqa: F401
    _risk_narrative,  # noqa: F401
    export_json,  # noqa: F401
    to_json,  # noqa: F401
)
from agent_bom.output.junit import (  # noqa: E402
    export_junit,  # noqa: F401
    to_junit,  # noqa: F401
)
from agent_bom.output.markdown import (  # noqa: E402
    export_markdown,  # noqa: F401
    to_markdown,  # noqa: F401
)
from agent_bom.output.sarif import (  # noqa: E402
    export_sarif,  # noqa: F401
    to_sarif,  # noqa: F401
)
from agent_bom.output.spdx_fmt import (  # noqa: E402
    export_spdx,  # noqa: F401
    to_spdx,  # noqa: F401
)

# ─── HTML Output (delegated to html.py) ──────────────────────────────────────


def to_html(report: AIBOMReport, blast_radii: list | None = None) -> str:
    """Generate a self-contained HTML report string."""
    from agent_bom.output.html import to_html as _to_html

    return _to_html(report, blast_radii or [])


def export_html(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Export report as a self-contained HTML file."""
    from agent_bom.output.html import export_html as _export_html

    _export_html(report, output_path, blast_radii or [])


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

    return _to_prometheus(report, blast_radii or [])


def export_prometheus(report: AIBOMReport, output_path: str, blast_radii: list | None = None) -> None:
    """Write Prometheus metrics to a .prom file."""
    from agent_bom.output.prometheus import export_prometheus as _export_prometheus

    _export_prometheus(report, output_path, blast_radii or [])


def push_to_gateway(
    gateway_url: str,
    report: AIBOMReport,
    blast_radii: list | None = None,
    job: str = "agent-bom",
    instance: str | None = None,
) -> None:
    """Push scan metrics to a Prometheus Pushgateway."""
    from agent_bom.output.prometheus import push_to_gateway as _push

    _push(gateway_url, report, blast_radii or [], job=job, instance=instance)


def push_otlp(
    endpoint: str,
    report: AIBOMReport,
    blast_radii: list | None = None,
) -> None:
    """Export metrics via OpenTelemetry OTLP/HTTP (requires agent-bom[otel])."""
    from agent_bom.output.prometheus import push_otlp as _push_otlp

    _push_otlp(endpoint, report, blast_radii or [])


# ─── Compact family — re-exported from .compact (see #1522 Phase 1a) ─────────
# Kept at the bottom so .compact can back-import `console`, `_sev_badge`, and
# `build_remediation_plan` lazily without a circular import.

from agent_bom.output.compact import (  # noqa: E402 — intentional bottom import
    _compact_detail,
    _coverage_bar,
    _iter_cis_bundles,
    _pct,
    _posture_grade_badge,
    print_compact_agents,
    print_compact_blast_radius,
    print_compact_cis_posture,
    print_compact_export_hint,
    print_compact_remediation,
    print_compact_summary,
)
