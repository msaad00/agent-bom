"""Composed Click option decorators for the ``scan`` command.

The public import stays stable at :func:`scan_options`, while the actual option
groups live in smaller helper modules by concern.
"""

from __future__ import annotations

from agent_bom.cli.options_sources import (
    enrichment_options,
    input_options,
    output_options,
    policy_options,
    scan_control_options,
    vex_options,
)
from agent_bom.cli.options_surfaces import (
    ai_remediation_options,
    cloud_options,
    compliance_options,
    discovery_options,
    iac_sast_options,
    integration_options,
    kubernetes_options,
    ml_platform_options,
    runtime_options,
)

# ── Composite decorator ────────────────────────────────────────────────────

# Order matters: click applies decorators bottom-up, so the first group
# listed here will have its options appear *last* in --help.  We list them
# in a logical reading order; the actual CLI help grouping is not affected
# since click sorts options alphabetically by default.

_ALL_GROUPS = [
    input_options,
    output_options,
    scan_control_options,
    enrichment_options,
    vex_options,
    policy_options,
    discovery_options,
    runtime_options,
    kubernetes_options,
    cloud_options,
    ml_platform_options,
    iac_sast_options,
    compliance_options,
    ai_remediation_options,
    integration_options,
]


def scan_options(fn):
    """Apply all scan CLI options in one decorator: ``@scan_options``."""
    for group in reversed(_ALL_GROUPS):
        fn = group(fn)
    return fn
