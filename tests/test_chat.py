"""Tests for agent-bom interactive chat engine."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_bom.chat import (
    ChatContext,
    _get_help_text,
    detect_intent,
    handle_message,
)


# ---------------------------------------------------------------------------
# Intent detection
# ---------------------------------------------------------------------------


class TestDetectIntent:
    def test_scan_intent(self):
        assert detect_intent("scan my system") == "scan"
        assert detect_intent("discover agents") == "scan"
        assert detect_intent("audit my setup") == "scan"

    def test_check_package_intent(self):
        assert detect_intent("check package lodash") == "check_package"
        assert detect_intent("is express vulnerable") == "check_package"
        assert detect_intent("cve for openai") == "check_package"

    def test_compliance_intent(self):
        assert detect_intent("show HIPAA compliance") == "compliance"
        assert detect_intent("am I SOC2 compliant?") == "compliance"
        assert detect_intent("NIST framework status") == "compliance"
        assert detect_intent("CMMC posture") == "compliance"

    def test_remediate_intent(self):
        assert detect_intent("how to fix these issues") == "remediate"
        assert detect_intent("remediate vulnerabilities") == "remediate"
        assert detect_intent("patch my packages") == "remediate"

    def test_blast_radius_intent(self):
        assert detect_intent("show blast radius") == "blast_radius"
        assert detect_intent("what is the impact?") == "blast_radius"
        assert detect_intent("show exposure") == "blast_radius"

    def test_inventory_intent(self):
        assert detect_intent("list agents") == "inventory"
        assert detect_intent("show agents") == "inventory"
        assert detect_intent("what agents do I have?") == "inventory"

    def test_help_intent(self):
        assert detect_intent("help") == "help"
        assert detect_intent("what can you do?") == "help"

    def test_status_intent(self):
        assert detect_intent("show status") == "status"
        assert detect_intent("what's my posture?") == "status"
        assert detect_intent("how secure am I?") == "status"

    def test_general_intent(self):
        assert detect_intent("hello there") == "general"
        assert detect_intent("tell me a joke") == "general"


# ---------------------------------------------------------------------------
# ChatContext
# ---------------------------------------------------------------------------


class TestChatContext:
    def test_add_message(self):
        ctx = ChatContext()
        ctx.add_message("user", "hello")
        assert len(ctx.history) == 1
        assert ctx.history[0] == {"role": "user", "content": "hello"}

    def test_history_bounded(self):
        ctx = ChatContext()
        for i in range(25):
            ctx.add_message("user", f"msg {i}")
        assert len(ctx.history) == 20

    def test_initial_state(self):
        ctx = ChatContext()
        assert ctx.last_scan_result is None
        assert ctx.last_agents is None
        assert ctx.last_blast_radii is None


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------


def test_help_text():
    text = _get_help_text()
    assert "scan" in text
    assert "compliance" in text
    assert "remediate" in text
    assert "exit" in text


# ---------------------------------------------------------------------------
# handle_message
# ---------------------------------------------------------------------------


def test_handle_help():
    async def _run():
        ctx = ChatContext()
        response = await handle_message("help", ctx)
        assert "scan" in response
        assert len(ctx.history) == 2  # user + assistant
    asyncio.run(_run())


def test_handle_status_no_data():
    async def _run():
        ctx = ChatContext()
        response = await handle_message("status", ctx)
        assert "No data" in response or "scan" in response.lower()
    asyncio.run(_run())


def test_handle_compliance_no_data():
    async def _run():
        ctx = ChatContext()
        response = await handle_message("show HIPAA compliance", ctx)
        assert "scan" in response.lower()
    asyncio.run(_run())


def test_handle_remediate_no_data():
    async def _run():
        ctx = ChatContext()
        response = await handle_message("fix my issues", ctx)
        assert "scan" in response.lower()
    asyncio.run(_run())


def test_handle_blast_radius_no_data():
    async def _run():
        ctx = ChatContext()
        response = await handle_message("show blast radius", ctx)
        assert "scan" in response.lower()
    asyncio.run(_run())


def test_handle_general_no_llm():
    async def _run():
        ctx = ChatContext()
        with patch("agent_bom.chat._ask_llm", return_value=None):
            response = await handle_message("hello there", ctx)
        assert "help" in response.lower()
    asyncio.run(_run())


def test_handle_general_with_llm():
    async def _run():
        ctx = ChatContext()
        with patch("agent_bom.chat._ask_llm", return_value="Hello! I'm agent-bom."):
            response = await handle_message("hello there", ctx)
        assert "agent-bom" in response
    asyncio.run(_run())


def test_handle_inventory():
    async def _run():
        ctx = ChatContext()
        with patch("agent_bom.discovery.discover_all", return_value=[]):
            response = await handle_message("list agents", ctx)
        assert "No AI agents" in response
    asyncio.run(_run())


def test_handle_scan_no_agents():
    async def _run():
        ctx = ChatContext()
        with patch("agent_bom.discovery.discover_all", return_value=[]):
            response = await handle_message("scan", ctx)
        assert "No AI agents" in response
    asyncio.run(_run())


def test_handle_check_package_no_spec():
    async def _run():
        ctx = ChatContext()
        response = await handle_message("check package", ctx)
        assert "specify" in response.lower() or "package" in response.lower()
    asyncio.run(_run())
