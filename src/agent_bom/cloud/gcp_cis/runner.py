"""Ordered GCP CIS check registry and the per-check execution loop."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning
from agent_bom.security import sanitize_text

from ._base import GCPCISReport, _seams

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")

# (CIS control id, check function name). Names resolve through the facade at
# run time so a patched ``gcp_cis_benchmark._check_*`` steers the run.
CHECK_REGISTRY: tuple[tuple[str, str], ...] = (
    ("1.1", "_check_1_1"),
    ("1.2", "_check_1_2"),
    ("1.3", "_check_1_3"),
    ("1.4", "_check_1_4"),
    ("1.5", "_check_1_5"),
    ("1.6", "_check_1_6"),
    ("1.7", "_check_1_7"),
    ("1.8", "_check_1_8"),
    ("1.9", "_check_1_9"),
    ("1.10", "_check_1_10"),
    ("1.11", "_check_1_11"),
    ("1.12", "_check_1_12"),
    ("1.13", "_check_1_13"),
    ("1.14", "_check_1_14"),
    ("1.15", "_check_1_15"),
    ("2.1", "_check_2_1"),
    ("2.2", "_check_2_2"),
    ("2.3", "_check_2_3"),
    ("2.4", "_check_2_4"),
    ("2.5", "_check_2_5"),
    ("2.6", "_check_2_6"),
    ("2.7", "_check_2_7"),
    ("2.8", "_check_2_8"),
    ("2.9", "_check_2_9"),
    ("2.10", "_check_2_10"),
    ("2.11", "_check_2_11"),
    ("2.12", "_check_2_12"),
    ("3.1", "_check_3_1"),
    ("3.2", "_check_3_2"),
    ("3.3", "_check_3_3"),
    ("3.4", "_check_3_4"),
    ("3.5", "_check_3_5"),
    ("3.6", "_check_3_6"),
    ("3.7", "_check_3_7"),
    ("3.8", "_check_3_8"),
    ("3.9", "_check_3_9"),
    ("3.10", "_check_3_10"),
    ("4.1", "_check_4_1"),
    ("4.2", "_check_4_2"),
    ("4.3", "_check_4_3"),
    ("4.4", "_check_4_4"),
    ("4.5", "_check_4_5"),
    ("4.6", "_check_4_6"),
    ("4.7", "_check_4_7"),
    ("4.8", "_check_4_8"),
    ("4.9", "_check_4_9"),
    ("4.11", "_check_4_11"),
    ("5.1", "_check_5_1"),
    ("5.2", "_check_5_2"),
    ("6.1", "_check_6_1"),
    ("6.2", "_check_6_2"),
    ("6.3", "_check_6_3"),
    ("6.4", "_check_6_4"),
    ("6.5", "_check_6_5"),
    ("6.6", "_check_6_6"),
    ("6.7", "_check_6_7"),
    ("7.1", "_check_7_1"),
    ("7.2", "_check_7_2"),
    ("7.3", "_check_7_3"),
)


def run_registered_checks(report: GCPCISReport, project_id: str, checks: list[str] | None) -> None:
    """Run every registered check (or the ``checks`` subset) in registry order."""
    facade = _seams()
    for check_id, check_name in CHECK_REGISTRY:
        if checks and check_id not in checks:
            continue
        try:
            report.checks.append(getattr(facade, check_name)(project_id))
        except Exception as exc:
            logger.warning("GCP CIS check %s failed with exception: %s", check_id, sanitize_text(exc))
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=f"Check {check_id}",
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=sanitize_discovery_warning(exc),
                )
            )
