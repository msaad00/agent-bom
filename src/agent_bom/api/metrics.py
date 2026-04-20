"""In-process counters for the enterprise control-plane surface.

These complement the existing scan / fleet / OIDC gauges exposed at
``/metrics``. The counters here cover the surfaces that a pilot team
watches on day 1: auth failures, rate-limit hits, compliance evidence
exports, and signature-algorithm mix.

Keep this module dependency-free (no prometheus_client) so it works in
the same environments the rest of the API does — the ``/metrics`` route
renders plain Prometheus text format.
"""

from __future__ import annotations

import threading
from collections import defaultdict


class _LabelledCounter:
    """Thread-safe counter keyed by a single label value."""

    __slots__ = ("_lock", "_values")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, int] = defaultdict(int)

    def inc(self, label: str, amount: int = 1) -> None:
        with self._lock:
            self._values[label] += amount

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._values)


_auth_failures = _LabelledCounter()  # labelled by reason (missing_key, invalid_key, ...)
_rate_limit_hits = _LabelledCounter()  # labelled by bucket name (global, tenant, ...)
_compliance_exports = _LabelledCounter()  # labelled by algorithm (Ed25519, HMAC-SHA256)
_compliance_export_bytes = _LabelledCounter()  # labelled by framework key
_scan_completions = _LabelledCounter()  # labelled by status (done, failed, cancelled)
_gateway_relays = _LabelledCounter()  # labelled by "<upstream>|<outcome>"


def record_auth_failure(reason: str) -> None:
    """Record an authentication failure (missing_key, invalid_key, expired_token, ...)."""
    _auth_failures.inc(reason)


def record_rate_limit_hit(bucket: str) -> None:
    """Record a rate-limit rejection by bucket (global, tenant, ingress, ...)."""
    _rate_limit_hits.inc(bucket)


def record_compliance_export(algorithm: str, framework_key: str, byte_count: int) -> None:
    """Record a compliance evidence bundle export."""
    _compliance_exports.inc(algorithm)
    _compliance_export_bytes.inc(framework_key, byte_count)


def record_scan_completion(status: str) -> None:
    """Record a scan outcome (done, failed, cancelled)."""
    _scan_completions.inc(status)


def record_gateway_relay(upstream: str, outcome: str) -> None:
    """Record a gateway relay event.

    ``upstream`` is the routing name (e.g. "jira"); ``outcome`` is one of
    ``forwarded``, ``blocked``, ``upstream_error``. Labelled as
    ``upstream|outcome`` in the Prometheus output so operators can
    rate() by either dimension.
    """
    _gateway_relays.inc(f"{upstream}|{outcome}")


def render_prometheus_lines() -> list[str]:
    """Return Prometheus text-format lines for all in-process counters."""
    lines: list[str] = []

    auth = _auth_failures.snapshot()
    lines.append("# HELP agent_bom_auth_failures_total API authentication failures by reason")
    lines.append("# TYPE agent_bom_auth_failures_total counter")
    if not auth:
        lines.append('agent_bom_auth_failures_total{reason="none"} 0')
    for reason, count in sorted(auth.items()):
        lines.append(f'agent_bom_auth_failures_total{{reason="{reason}"}} {count}')

    rate = _rate_limit_hits.snapshot()
    lines.append("# HELP agent_bom_rate_limit_hits_total Requests rejected by a rate limiter")
    lines.append("# TYPE agent_bom_rate_limit_hits_total counter")
    if not rate:
        lines.append('agent_bom_rate_limit_hits_total{bucket="none"} 0')
    for bucket, count in sorted(rate.items()):
        lines.append(f'agent_bom_rate_limit_hits_total{{bucket="{bucket}"}} {count}')

    compliance = _compliance_exports.snapshot()
    lines.append("# HELP agent_bom_compliance_exports_total Compliance evidence bundles exported by signing algorithm")
    lines.append("# TYPE agent_bom_compliance_exports_total counter")
    if not compliance:
        lines.append('agent_bom_compliance_exports_total{algorithm="none"} 0')
    for algorithm, count in sorted(compliance.items()):
        lines.append(f'agent_bom_compliance_exports_total{{algorithm="{algorithm}"}} {count}')

    bundle_bytes = _compliance_export_bytes.snapshot()
    lines.append("# HELP agent_bom_compliance_export_bytes_total Total bytes of compliance bundles served by framework")
    lines.append("# TYPE agent_bom_compliance_export_bytes_total counter")
    if not bundle_bytes:
        lines.append('agent_bom_compliance_export_bytes_total{framework="none"} 0')
    for framework, count in sorted(bundle_bytes.items()):
        lines.append(f'agent_bom_compliance_export_bytes_total{{framework="{framework}"}} {count}')

    scans = _scan_completions.snapshot()
    lines.append("# HELP agent_bom_scan_completions_total Completed scans by final status")
    lines.append("# TYPE agent_bom_scan_completions_total counter")
    if not scans:
        lines.append('agent_bom_scan_completions_total{status="none"} 0')
    for status, count in sorted(scans.items()):
        lines.append(f'agent_bom_scan_completions_total{{status="{status}"}} {count}')

    relays = _gateway_relays.snapshot()
    lines.append("# HELP agent_bom_gateway_relays_total Multi-MCP gateway relay events by upstream and outcome")
    lines.append("# TYPE agent_bom_gateway_relays_total counter")
    if not relays:
        lines.append('agent_bom_gateway_relays_total{upstream="none",outcome="none"} 0')
    for label, count in sorted(relays.items()):
        upstream, _, outcome = label.partition("|")
        lines.append(f'agent_bom_gateway_relays_total{{upstream="{upstream}",outcome="{outcome}"}} {count}')

    return lines


def reset_for_tests() -> None:
    """Reset all counters — test-only entry point."""
    for counter in (
        _auth_failures,
        _rate_limit_hits,
        _compliance_exports,
        _compliance_export_bytes,
        _scan_completions,
        _gateway_relays,
    ):
        with counter._lock:  # noqa: SLF001
            counter._values.clear()  # noqa: SLF001
