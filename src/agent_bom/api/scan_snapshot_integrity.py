"""Source and derived-content identity for versioned scan snapshot inputs."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.api.models import ScanJob


def snapshot_source_digest(job: ScanJob) -> str:
    """Bind derived inputs to the entire retained source, including JSON types."""
    # ScanJob iteration is shallow: avoid copying the entire JSON result merely
    # to hash it. Request/model leaves still use their JSON serializer.
    payload = dict(job)

    def encode(value: Any) -> Any:
        return value.model_dump(mode="json") if hasattr(value, "model_dump") else str(value)

    return hashlib.sha256(json.dumps(payload, default=encode, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def snapshot_content_digest(reach: Any, rows: list[dict[str, Any]]) -> str:
    payload = [reach, [row["payload"] for row in rows]]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()).hexdigest()
