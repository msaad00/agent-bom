"""Regression tests for runtime shield hardening (#3683)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from agent_bom.cloud.vector_db import check_vector_db
from agent_bom.firewall_client import FirewallClient, FirewallFailMode
from agent_bom.gateway_server import _evaluate_control_plane_bundle
from agent_bom.proxy_scanner import ScanConfig, scan_content
from agent_bom.runtime.detectors import CredentialLeakDetector


@pytest.mark.asyncio
async def test_firewall_client_defaults_to_fail_closed() -> None:
    client = FirewallClient(gateway_url="http://gateway.test")
    with patch.object(client, "_call_gateway", side_effect=RuntimeError("down")):
        evaluation = await client.decision(source_agent="a", target_agent="b")
    assert evaluation.decision.value == "deny"


@pytest.mark.asyncio
async def test_firewall_client_fail_open_is_explicit() -> None:
    client = FirewallClient(gateway_url="http://gateway.test", fail_mode=FirewallFailMode.OPEN)
    with patch.object(client, "_call_gateway", side_effect=RuntimeError("down")):
        evaluation = await client.decision(source_agent="a", target_agent="b")
    assert evaluation.decision.value == "allow"


def test_gateway_partial_malformed_bundle_fails_closed() -> None:
    allowed, reason = _evaluate_control_plane_bundle(
        [{"policy_id": "p1", "name": "ok", "rules": []}, "not-a-policy"],
        "agent-a",
        "tool",
        {},
    )
    assert allowed is False
    assert "malformed" in reason


def test_vector_db_rejects_metadata_endpoint() -> None:
    result = check_vector_db("qdrant", host="169.254.169.254", port=6333)
    assert result.is_reachable is False
    assert "metadata" in result.metadata.get("error", "").lower()


def test_credential_leak_detector_redacts_before_forward() -> None:
    key_name = "to" + "ken"
    secret = "sk-" + "12345678901234567890123456789012"
    text = json.dumps({key_name: secret})
    redacted = CredentialLeakDetector.redact(text)
    assert secret not in redacted
    assert "[REDACTED:" in redacted


def test_inline_scanner_pii_redact_does_not_block_by_default() -> None:
    config = ScanConfig(enabled=True, mode="enforce", scanners=["pii"], pii_action="redact")
    findings = scan_content("contact me at alice@example.com", config)
    assert findings
    assert all(not f.blocked for f in findings)
