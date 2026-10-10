"""Store-backed runtime enrichment for graph investigation adapters.

Kept outside pure topology derivation so graph projections do not import
store selection, database pools or API startup through this dependency.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _enrich_loaded_graph_runtime_evidence(graph: Any, tenant_id: str) -> Any:
    """Best-effort CWPP workload runtime-evidence annotate on a loaded graph.

    Covers snapshots persisted before enrich-at-persist landed. Tenant mismatch
    or empty store is a no-op; never raises into graph routes.
    """
    try:
        from agent_bom.cloud.runtime_workload_evidence import (
            RuntimeWorkloadEvidenceIndex,
            enrich_graph_workload_runtime_evidence,
        )
        from agent_bom.cloud.runtime_workload_evidence_store import get_runtime_workload_evidence_store

        index = RuntimeWorkloadEvidenceIndex.from_store(get_runtime_workload_evidence_store(), tenant_id)
        enrich_graph_workload_runtime_evidence(graph, index)
    except Exception:  # noqa: BLE001 — investigation reads must not fail closed on enrich
        logger.debug("workload runtime evidence load enrich skipped", exc_info=False)
    return graph
