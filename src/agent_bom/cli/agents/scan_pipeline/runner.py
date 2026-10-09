"""Run the scan stages in order and record each stage's wall time."""

from __future__ import annotations

import time
from collections.abc import Callable

from agent_bom.ast.project_scope import project_analysis_scope
from agent_bom.cli._common import logger
from agent_bom.cli.agents.scan_pipeline import (
    discovery,
    enrichment,
    gates,
    graph,
    inventory,
    late,
    matching,
    output,
    policy,
    preflight,
    prepare,
    report,
)
from agent_bom.cli.agents.scan_pipeline.options import ScanOptions
from agent_bom.cli.agents.scan_pipeline.state import ScanState, StopScan

Stage = Callable[[ScanOptions, ScanState], None]

STAGES: tuple[tuple[str, Stage], ...] = (
    ("options", prepare.run_prepare),
    ("preflight", preflight.run_preflight),
    ("discovery", discovery.run_discovery),
    ("inventory", inventory.run_inventory),
    ("matching", matching.run_matching),
    ("enrichment", enrichment.run_enrichment),
    ("report", report.run_report),
    ("graph", graph.run_graph),
    ("ai_assets", late.run_ai_asset_scanners),
    ("policy", policy.run_policy),
    ("output", output.run_output),
    ("gates", gates.run_gates),
)


def _record_stage_time(st: ScanState, name: str, elapsed: float) -> None:
    # Per-stage timings sit beside the coarse step timings under a ``stage:``
    # prefix; the console breakdown reads only its fixed step names, so these
    # surface solely through the debug log that ``--verbose`` enables.
    st.stage_timings[name] = elapsed
    if st.ctx is not None:
        st.ctx.step_timings.update({f"stage:{key}": value for key, value in st.stage_timings.items()})
    logger.debug("scan stage %s took %.3fs", name, elapsed)


@project_analysis_scope()
def run_scan(opts: ScanOptions, stages: tuple[tuple[str, Stage], ...] = STAGES) -> None:
    """Execute ``stages`` for one invocation; a stage may end the run early with :class:`StopScan`."""
    st = ScanState()
    try:
        for name, stage in stages:
            started = time.monotonic()
            try:
                stage(opts, st)
            finally:
                _record_stage_time(st, name, time.monotonic() - started)
    except StopScan:
        return
