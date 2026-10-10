"""The main ``scan`` command — discover, resolve, scan, report.

The command body is a staged pipeline (``scan_pipeline``): each stage is a
bounded function over a typed :class:`ScanOptions` and :class:`ScanState`.
Patch targets (``discover_all``, ``extract_packages``, etc.) are bound on
``agent_bom.cli.agents`` and resolved at call time so tests can patch the
package namespace; ``to_json`` here is the report-projection seam the output
stage calls through.
"""

from __future__ import annotations

import inspect
from typing import Any

import click

from agent_bom.cli._scan_help import TieredCommand
from agent_bom.cli.agents.scan_pipeline.helpers import (
    _benchmark_scan_issues,
    _cloud_scan_scope,
    _compute_scan_id,
    _expand_docker_mcp_packages,
)
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.runner import run_scan
from agent_bom.cli.options import scan_options
from agent_bom.output import to_json

__all__ = [
    "_benchmark_scan_issues",
    "_cloud_scan_scope",
    "_compute_scan_id",
    "_expand_docker_mcp_packages",
    "scan",
    "to_json",
]


@click.command(cls=TieredCommand)
@click.argument(
    "path",
    required=False,
    type=click.Path(exists=True, file_okay=False),
    metavar="[PATH]",
)
@scan_options
def scan(**options: Any) -> None:
    """Discover agents, extract dependencies, scan for vulnerabilities.

    \b
    Exit codes (a non-zero exit is a scan verdict, not a crash — the report
    is still printed and still complete):
      0  Clean — no violations, no vulnerabilities at or above threshold
           (also exits 0 when only --warn threshold is breached)
      1  Fail — policy failure, or vulnerabilities found at or above
                --fail-on-severity / --fail-on-kev / --fail-if-ai-risk.
                Two gates also fail closed with no flag set: a known-malicious
                package (typosquat / dependency confusion) and a scan that did
                not complete. This is why `scan --demo` exits 1.
      2  Usage error — an option or input is invalid.
      3  Stale vulnerability database while --require-fresh-db is enabled.
    \b
    Full contract: https://koda-ai-studio.github.io/agent-bom/reference/exit-codes/
    """

    run_scan(ScanOptions(**options))


# Keyword binding stays strict (``ScanOptions`` rejects unknown names); expose
# the same parameter list to introspection so callers can validate kwargs.
scan.callback.__signature__ = inspect.signature(ScanOptions)  # type: ignore[union-attr]
