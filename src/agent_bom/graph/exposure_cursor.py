"""Validate continuation scope before reading graph exposure evidence."""

import base64
import json
from typing import Any


def decode_exposure_cursor(cursor: str, *, scope: str, scan_id: str | None) -> dict[str, Any]:
    if len(cursor) > 4096:
        raise ValueError
    continuation = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
    if (
        not isinstance(continuation, dict)
        or continuation.get("v") != 1
        or continuation.get("scope") != scope
        or not isinstance(continuation.get("scan"), str)
        or not continuation["scan"]
        or "\x00" in continuation["scan"]
        or (scan_id and scan_id != continuation["scan"])
        or type(continuation.get("offset")) is not int
        or not 0 < continuation["offset"] <= 100_000_000
        or not isinstance(continuation.get("revision"), str)
    ):
        raise ValueError
    return continuation
