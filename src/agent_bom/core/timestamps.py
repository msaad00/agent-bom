"""Pure identity timestamp parsing shared by credential and governance decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_identity_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    # Tolerate the trailing-Z form some IdPs emit.
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
