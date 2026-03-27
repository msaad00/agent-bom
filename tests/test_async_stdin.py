"""Tests for async stdin fallbacks used by proxy and runtime server."""

from __future__ import annotations

import io
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.async_stdin import create_async_stdin_reader, read_async_stdin_line


@pytest.mark.asyncio
async def test_create_async_stdin_reader_uses_pipe_when_available():
    mock_loop = MagicMock()
    mock_loop.connect_read_pipe = AsyncMock()

    with patch("agent_bom.async_stdin.asyncio.get_running_loop", return_value=mock_loop):
        reader = await create_async_stdin_reader()

    assert reader is not None
    mock_loop.connect_read_pipe.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_async_stdin_reader_falls_back_on_pipe_error():
    mock_loop = MagicMock()
    mock_loop.connect_read_pipe = AsyncMock(side_effect=OSError(22, "Invalid argument"))

    with patch("agent_bom.async_stdin.asyncio.get_running_loop", return_value=mock_loop):
        reader = await create_async_stdin_reader()

    assert reader is None


@pytest.mark.asyncio
async def test_read_async_stdin_line_thread_fallback_encodes_text():
    fake_stdin = io.StringIO('{"jsonrpc":"2.0"}\n')

    with patch("agent_bom.async_stdin.sys.stdin", fake_stdin):
        line = await read_async_stdin_line(None)

    assert line == b'{"jsonrpc":"2.0"}\n'
