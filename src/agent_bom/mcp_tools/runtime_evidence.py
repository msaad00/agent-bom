"""MCP tool: ingest CWPP runtime/EDR workload signals (#4158 stage 4)."""

from __future__ import annotations

import json
import logging
from typing import Any

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def runtime_evidence_ingest_impl(
    *,
    source_id: str,
    secret: str,
    signals_json: str,
    _truncate_response: Any,
) -> str:
    """Authenticate a registered source and ingest a JSON array of signals."""
    try:
        from agent_bom.cloud.runtime_workload_evidence import (
            SourceAuthenticationError,
            ingest_runtime_signals_payload,
        )

        payload = json.loads(signals_json)
        result = ingest_runtime_signals_payload(
            source_id=source_id,
            secret=secret,
            payload=payload,
            persist=True,
        )
        return _truncate_response(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    except SourceAuthenticationError:
        return json.dumps({"error": "runtime evidence source authentication failed"})
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return json.dumps({"error": sanitize_error(exc)})
    except Exception as exc:  # noqa: BLE001
        logger.exception("MCP runtime_evidence_ingest error")
        return json.dumps({"error": sanitize_error(exc)})


__all__ = ["runtime_evidence_ingest_impl"]
