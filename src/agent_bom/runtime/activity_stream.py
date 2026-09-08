"""Bounded SSE decoding for the durable gateway activity contract."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

MAX_FRAME_BYTES = 32 * 1024 * 1024


def decode_activity_stream(chunks: Iterable[bytes]) -> Iterator[dict[str, Any]]:
    """Yield complete frames only; a disconnected partial frame is never committed.

    Consumers checkpoint the returned id only after processing the entire data
    batch. A gap is terminal and must never be silently replaced by a fresh cursor.
    """
    buffer = b""
    lines: list[str] = []
    frame_bytes = 0
    for chunk in chunks:
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            frame_bytes += len(line) + 1
            if frame_bytes > MAX_FRAME_BYTES:
                raise ValueError("Activity stream frame exceeds limit")
            decoded = line.rstrip(b"\r").decode("utf-8")
            if decoded:
                lines.append(decoded)
                continue
            frame = _frame(lines)
            lines = []
            frame_bytes = 0
            if frame is not None:
                yield frame
        if frame_bytes + len(buffer) > MAX_FRAME_BYTES:
            raise ValueError("Activity stream frame exceeds limit")


def _frame(lines: list[str]) -> dict[str, Any] | None:
    event, cursor, data = "message", "", []
    for line in lines:
        key, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if key == "event":
            event = value
        elif key == "id":
            cursor = value
        elif key == "data":
            data.append(value)
    if not data:
        return None
    try:
        payload = json.loads("\n".join(data))
    except (ValueError, RecursionError):
        raise ValueError("Invalid activity stream JSON") from None
    if not isinstance(payload, dict):
        raise ValueError("Invalid activity stream payload")
    if event in {"activity", "checkpoint"}:
        if (
            payload.get("schema_version") != "gateway.activity.stream.v1"
            or not cursor
            or payload.get("next_cursor") != cursor
            or not isinstance(payload.get("events"), list)
        ):
            raise ValueError("Invalid activity stream checkpoint")
    elif event not in {"gap", "unavailable", "reconnect"}:
        raise ValueError("Unknown activity stream event")
    return {"event": event, "id": cursor, "data": payload}
