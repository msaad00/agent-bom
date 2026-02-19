"""Prometheus exposition format output for agent-bom reports.

Emits scan results as Prometheus text-format metrics so they can be:
  - Scraped by a Prometheus server directly (write to a .prom file in a
    node_exporter textfile directory)
  - Pushed to a Prometheus Pushgateway via --push-gateway
  - Integrated with Grafana for real-time dashboards

Zero external dependencies — uses only stdlib ``urllib`` for Pushgateway push.

Usage from cli.py::

    from agent_bom.output.prometheus import to_prometheus, push_to_gateway

    text = to_prometheus(report, blast_radii)
    push_to_gateway("http://localhost:9091", text, job="agent-bom")
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from agent_bom.models import AIBOMReport, BlastRadius, Severity

# ─── Metric name constants ─────────────────────────────────────────────────

_PREFIX = "agent_bom"


def _label(key: str, value: str) -> str:
    """Escape a label value for Prometheus exposition format."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'{key}="{escaped}"'


def _labels(*pairs: tuple[str, str]) -> str:
    if not pairs:
        return ""
    return "{" + ",".join(_label(k, v) for k, v in pairs) + "}"


def _metric(name: str, value: float | int, *label_pairs: tuple[str, str]) -> str:
    return f"{_PREFIX}_{name}{_labels(*label_pairs)} {value}"


# ─── Core builder ─────────────────────────────────────────────────────────


def to_prometheus(
    report: AIBOMReport,
    blast_radii: Optional[list[BlastRadius]] = None,
) -> str:
    """Convert an AIBOMReport to Prometheus text exposition format.

    Returns a string ready to be:
      - Written to a file and scraped by node_exporter textfile collector
      - POSTed to a Prometheus Pushgateway
      - Emitted to stdout for CI piping

    Metrics emitted
    ---------------
    agent_bom_info                         Gauge  Tool/scan metadata (always 1)
    agent_bom_scan_timestamp_seconds       Gauge  Unix timestamp of the scan
    agent_bom_agents_total                 Gauge  Number of agents discovered
    agent_bom_mcp_servers_total            Gauge  Number of MCP servers
    agent_bom_packages_total               Gauge  Total packages scanned
    agent_bom_vulnerabilities_total        Gauge  Vulns by severity label
    agent_bom_blast_radius_score           Gauge  Risk score per vuln (0–10)
    agent_bom_kev_findings_total           Gauge  CISA KEV count
    agent_bom_fixable_vulnerabilities_total Gauge Vulns with a known fix
    agent_bom_credentials_exposed_total    Gauge  Creds exposed, per agent
    agent_bom_agent_vulnerabilities_total  Gauge  Per-agent, per-severity counts
    """
    brs = blast_radii or []
    lines: list[str] = []

    def header(name: str, help_text: str, metric_type: str = "gauge") -> None:
        lines.append(f"# HELP {_PREFIX}_{name} {help_text}")
        lines.append(f"# TYPE {_PREFIX}_{name} {metric_type}")

    # ── agent_bom_info ────────────────────────────────────────────────────
    header("info", "agent-bom tool metadata (always 1)")
    lines.append(
        _metric("info", 1,
                ("version", report.tool_version),
                ("scan_at", report.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")))
    )
    lines.append("")

    # ── agent_bom_scan_timestamp_seconds ─────────────────────────────────
    header("scan_timestamp_seconds", "Unix timestamp of the last completed scan")
    ts = report.generated_at.timestamp()
    lines.append(_metric("scan_timestamp_seconds", ts))
    lines.append("")

    # ── Totals ────────────────────────────────────────────────────────────
    header("agents_total", "Total number of AI agents discovered")
    lines.append(_metric("agents_total", report.total_agents))
    lines.append("")

    header("mcp_servers_total", "Total number of MCP servers across all agents")
    lines.append(_metric("mcp_servers_total", report.total_servers))
    lines.append("")

    header("packages_total", "Total number of packages (direct + transitive) scanned")
    lines.append(_metric("packages_total", report.total_packages))
    lines.append("")

    # ── Vulnerability counts by severity ─────────────────────────────────
    header("vulnerabilities_total",
           "Total vulnerabilities found, broken down by severity")
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity if s != Severity.NONE}
    for br in brs:
        sev = br.vulnerability.severity.value
        if sev in sev_counts:
            sev_counts[sev] += 1
    for sev, count in sev_counts.items():
        lines.append(_metric("vulnerabilities_total", count, ("severity", sev)))
    lines.append("")

    # ── CISA KEV count ────────────────────────────────────────────────────
    header("kev_findings_total",
           "Number of findings in the CISA Known Exploited Vulnerabilities catalog")
    kev_count = sum(1 for br in brs if br.vulnerability.is_kev)
    lines.append(_metric("kev_findings_total", kev_count))
    lines.append("")

    # ── Fixable vulns ─────────────────────────────────────────────────────
    header("fixable_vulnerabilities_total",
           "Number of vulnerabilities that have a known fixed version available")
    fixable = sum(1 for br in brs if br.vulnerability.fixed_version)
    lines.append(_metric("fixable_vulnerabilities_total", fixable))
    lines.append("")

    # ── Per-vulnerability blast radius scores ─────────────────────────────
    if brs:
        header("blast_radius_score",
               "Blast radius risk score per vulnerability (0-10 scale)")
        for br in brs:
            v = br.vulnerability
            lines.append(
                _metric(
                    "blast_radius_score",
                    round(br.risk_score, 3),
                    ("vuln_id", v.id),
                    ("package", br.package.name),
                    ("version", br.package.version),
                    ("severity", v.severity.value),
                    ("ecosystem", br.package.ecosystem),
                    ("fixable", "1" if v.fixed_version else "0"),
                    ("kev", "1" if v.is_kev else "0"),
                )
            )
        lines.append("")

        # ── EPSS scores ───────────────────────────────────────────────────
        epss_brs = [br for br in brs if br.vulnerability.epss_score is not None]
        if epss_brs:
            header("vulnerability_epss_score",
                   "EPSS exploit probability score (0.0-1.0) per vulnerability")
            for br in epss_brs:
                v = br.vulnerability
                lines.append(
                    _metric(
                        "vulnerability_epss_score",
                        round(v.epss_score, 5),  # type: ignore[arg-type]
                        ("vuln_id", v.id),
                        ("package", br.package.name),
                        ("severity", v.severity.value),
                    )
                )
            lines.append("")

        # ── CVSS scores ───────────────────────────────────────────────────
        cvss_brs = [br for br in brs if br.vulnerability.cvss_score is not None]
        if cvss_brs:
            header("vulnerability_cvss_score",
                   "CVSS base score (0.0-10.0) per vulnerability")
            for br in cvss_brs:
                v = br.vulnerability
                lines.append(
                    _metric(
                        "vulnerability_cvss_score",
                        round(v.cvss_score, 2),  # type: ignore[arg-type]
                        ("vuln_id", v.id),
                        ("package", br.package.name),
                        ("severity", v.severity.value),
                    )
                )
            lines.append("")

    # ── Per-agent breakdowns ───────────────────────────────────────────────
    header("agent_vulnerabilities_total",
           "Number of vulnerabilities per agent, broken down by severity")
    # Build agent→severity→count
    agent_sev: dict[str, dict[str, int]] = {}
    for br in brs:
        for agent in br.affected_agents:
            if agent.name not in agent_sev:
                agent_sev[agent.name] = {s.value: 0 for s in Severity if s != Severity.NONE}
            sev = br.vulnerability.severity.value
            if sev in agent_sev[agent.name]:
                agent_sev[agent.name][sev] += 1
    # Also emit 0-counts for agents with no vulns
    for agent in report.agents:
        if agent.name not in agent_sev:
            agent_sev[agent.name] = {s.value: 0 for s in Severity if s != Severity.NONE}
    for agent_name, sev_map in sorted(agent_sev.items()):
        for sev, count in sev_map.items():
            lines.append(
                _metric("agent_vulnerabilities_total", count,
                        ("agent", agent_name), ("severity", sev))
            )
    lines.append("")

    header("credentials_exposed_total",
           "Number of distinct credentials exposed per agent")
    for agent in report.agents:
        cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
        lines.append(
            _metric("credentials_exposed_total", cred_count, ("agent", agent.name))
        )
    lines.append("")

    return "\n".join(lines)


# ─── File export ───────────────────────────────────────────────────────────


def export_prometheus(
    report: AIBOMReport,
    output_path: str,
    blast_radii: Optional[list[BlastRadius]] = None,
) -> None:
    """Write Prometheus text to a file (e.g. for node_exporter textfile collector)."""
    text = to_prometheus(report, blast_radii)
    Path(output_path).write_text(text, encoding="utf-8")


# ─── Pushgateway push ─────────────────────────────────────────────────────


class PushgatewayError(Exception):
    """Raised when the Prometheus Pushgateway push fails."""


def push_to_gateway(
    gateway_url: str,
    report: AIBOMReport,
    blast_radii: Optional[list[BlastRadius]] = None,
    job: str = "agent-bom",
    instance: Optional[str] = None,
    timeout: int = 15,
) -> None:
    """Push scan metrics to a Prometheus Pushgateway.

    Args:
        gateway_url: Base URL of the Pushgateway, e.g. ``http://localhost:9091``
        report: The AI-BOM report to push
        blast_radii: Blast radius analysis results
        job: Prometheus job label (default ``"agent-bom"``)
        instance: Optional instance label (e.g. hostname or pipeline run ID)
        timeout: HTTP request timeout in seconds

    Raises:
        PushgatewayError: If the HTTP push fails
    """
    # Enforce http/https only — reject file://, ftp://, etc.
    parsed_scheme = gateway_url.split("://", 1)[0].lower()
    if parsed_scheme not in ("http", "https"):
        raise PushgatewayError(
            f"Pushgateway URL must use http:// or https://, got: {gateway_url!r}"
        )

    text = to_prometheus(report, blast_radii)

    url = gateway_url.rstrip("/") + f"/metrics/job/{job}"
    if instance:
        url += f"/instance/{instance}"

    data = text.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
    )

    try:
        # nosec B310 — URL scheme restricted to http/https above
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status not in (200, 202):
                raise PushgatewayError(
                    f"Pushgateway returned HTTP {resp.status}"
                )
    except urllib.error.HTTPError as e:
        raise PushgatewayError(f"Pushgateway HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise PushgatewayError(f"Cannot reach Pushgateway at {gateway_url}: {e.reason}") from e


# ─── OpenTelemetry OTLP export (optional dep) ─────────────────────────────


def push_otlp(
    endpoint: str,
    report: AIBOMReport,
    blast_radii: Optional[list[BlastRadius]] = None,
    timeout: int = 15,
) -> None:
    """Export metrics via OpenTelemetry OTLP/HTTP.

    Requires ``opentelemetry-exporter-otlp-proto-http`` to be installed::

        pip install agent-bom[otel]

    Args:
        endpoint: OTLP collector endpoint, e.g. ``http://localhost:4318``
                  (the ``/v1/metrics`` path is appended automatically)
        report: The AI-BOM report to export
        blast_radii: Blast radius analysis results
        timeout: HTTP request timeout in seconds

    Raises:
        ImportError: If opentelemetry packages are not installed
        RuntimeError: If the OTLP export fails
    """
    try:
        from opentelemetry import metrics as otel_metrics
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    except ImportError as exc:
        raise ImportError(
            "OpenTelemetry packages are required for OTLP export. "
            "Install them with: pip install agent-bom[otel]\n"
            "  (opentelemetry-api opentelemetry-sdk "
            "opentelemetry-exporter-otlp-proto-http)"
        ) from exc

    brs = blast_radii or []

    resource = Resource(attributes={
        SERVICE_NAME: "agent-bom",
        "agent_bom.version": report.tool_version,
    })

    otlp_url = endpoint.rstrip("/") + "/v1/metrics"
    exporter = OTLPMetricExporter(endpoint=otlp_url, timeout=timeout)
    reader = PeriodicExportingMetricReader(exporter, export_interval_millis=1000)
    provider = MeterProvider(resource=resource, metric_readers=[reader])
    otel_metrics.set_meter_provider(provider)

    meter = otel_metrics.get_meter("agent_bom", version=report.tool_version)

    # Emit as observable gauges (snapshot semantics)
    def _agents_cb(options):  # noqa: ANN001
        yield otel_metrics.Observation(report.total_agents)

    def _servers_cb(options):
        yield otel_metrics.Observation(report.total_servers)

    def _packages_cb(options):
        yield otel_metrics.Observation(report.total_packages)

    def _kev_cb(options):
        yield otel_metrics.Observation(sum(1 for br in brs if br.vulnerability.is_kev))

    meter.create_observable_gauge("agent_bom.agents_total",
                                   callbacks=[_agents_cb],
                                   description="Total AI agents discovered")
    meter.create_observable_gauge("agent_bom.mcp_servers_total",
                                   callbacks=[_servers_cb],
                                   description="Total MCP servers")
    meter.create_observable_gauge("agent_bom.packages_total",
                                   callbacks=[_packages_cb],
                                   description="Total packages scanned")
    meter.create_observable_gauge("agent_bom.kev_findings_total",
                                   callbacks=[_kev_cb],
                                   description="CISA KEV findings")

    # Severity breakdown via ObservableGauge per severity
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity if s != Severity.NONE}
    for br in brs:
        sev = br.vulnerability.severity.value
        if sev in sev_counts:
            sev_counts[sev] += 1

    for sev_value, count in sev_counts.items():
        _count = count  # capture
        _sev = sev_value

        def _vuln_cb(options, c=_count, s=_sev):
            yield otel_metrics.Observation(c, {"severity": s})

        meter.create_observable_gauge(
            "agent_bom.vulnerabilities_total",
            callbacks=[_vuln_cb],
            description="Vulnerabilities by severity",
        )

    # Force flush
    provider.force_flush(timeout_millis=timeout * 1000)
    provider.shutdown()
