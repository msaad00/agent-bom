"""Operator self-posture API route — agent-bom audits its OWN control plane.

Read-only endpoint that surfaces the same honest deployment-hardening posture
as the ``agent-bom self-audit`` CLI, so operators (and headless callers) can
see the security + governance posture of THEIR OWN instance from the API.
No new inspection logic lives here — the checks are computed by
:func:`agent_bom.self_posture.self_posture`, which reads configuration only
(never a secret value, never the network, never a write).

Endpoints:
    GET /v1/self-posture   this instance's own security + governance posture
"""

from __future__ import annotations

from typing import Any, cast

import anyio.to_thread
from fastapi import APIRouter

from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])


@router.get("/self-posture", tags=["self-posture"])
async def get_self_posture() -> dict[str, Any]:
    """Return this agent-bom deployment's own security + governance posture.

    Honest per-check results (pass/fail/warn/unknown) over API authentication,
    database tenant isolation, audit-log integrity signing, secret sealing, and
    the dependency attack surface. Distribution enumeration is offloaded to a
    worker thread so the event loop is never blocked (non-negotiable §7).
    """
    from agent_bom.self_posture import self_posture

    return await anyio.to_thread.run_sync(self_posture)
