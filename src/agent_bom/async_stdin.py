"""Async stdin helpers with a safe fallback for platforms without pipe transport."""

from __future__ import annotations

import asyncio
import logging
import sys

logger = logging.getLogger(__name__)


def _stdin_stream():
    """Return a binary-capable stdin stream when available."""
    return getattr(sys.stdin, "buffer", sys.stdin)


async def create_async_stdin_reader() -> asyncio.StreamReader | None:
    """Attach stdin to an asyncio StreamReader when pipe transport is supported.

    Returns ``None`` when the current platform/event loop cannot attach stdin as
    a pipe transport. Callers should then fall back to ``read_async_stdin_line``.
    """
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    try:
        await loop.connect_read_pipe(lambda: protocol, _stdin_stream())
        return reader
    except (NotImplementedError, ValueError, OSError) as exc:
        logger.warning("stdin pipe transport unavailable (%s); using thread-backed stdin reader", exc)
        return None


async def read_async_stdin_line(reader: asyncio.StreamReader | None) -> bytes:
    """Read one line from stdin using an asyncio reader or a thread fallback."""
    if reader is not None:
        return await reader.readline()

    line = await asyncio.to_thread(_stdin_stream().readline)
    if isinstance(line, bytes):
        return line
    if isinstance(line, str):
        return line.encode("utf-8")
    return b""
