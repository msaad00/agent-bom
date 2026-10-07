"""Bounded campaign list excerpts; workflow actions retain complete membership."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from fastapi import HTTPException


def campaign_page(tenant_id: str, campaigns: list[dict[str, Any]], *, limit: int = 25, cursor: str | None = None) -> dict[str, Any]:
    if isinstance(limit, bool) or not 1 <= limit <= 100:
        raise HTTPException(status_code=400, detail="Campaign page limit must be between 1 and 100.")
    identity = [(row["id"], row.get("version"), row.get("membership_fingerprint"), row.get("priority_score")) for row in campaigns]
    fingerprint = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    offset = 0
    if cursor:
        try:
            if len(cursor) > 512:
                raise ValueError("oversized cursor")
            value = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
            offset = value["offset"]
            if type(offset) is not int or offset < 0 or not isinstance(value.get("tenant"), str):
                raise ValueError("invalid cursor shape")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise HTTPException(status_code=400, detail="Invalid campaign list cursor.") from exc
        if value.get("tenant") != tenant_id or value.get("fingerprint") != fingerprint or offset >= len(campaigns):
            raise HTTPException(status_code=409, detail="Campaign list changed; refresh before continuing.")
    page = []
    for row in campaigns[offset : offset + limit]:
        members = row["finding_ids"]
        page.append({**row, "finding_ids": members[:25], "finding_ids_truncated": len(members) > 25})
    next_offset = offset + len(page)
    has_more = next_offset < len(campaigns)
    next_cursor = None
    if has_more:
        value = {"tenant": tenant_id, "fingerprint": fingerprint, "offset": next_offset}
        next_cursor = base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
    return {
        "campaigns": page,
        "count": len(page),
        "total_campaigns": len(campaigns),
        "limit": limit,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }
