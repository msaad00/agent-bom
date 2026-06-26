"""Agent-mode envelope must never emit credential values as clear text.

The machine-readable envelope is routinely captured and logged by automation
callers, so any value under a credential-named key is masked at the single
serialization choke point (``dumps_envelope``), while reference labels, entity
types, and non-secret fields like ``token_budget`` are preserved.
"""

from __future__ import annotations

import json

from agent_bom.cli._agent_mode import dumps_envelope


def test_envelope_redacts_secret_keyed_values_but_keeps_references() -> None:
    payload = {
        "data": {
            "password": "hunter2-real-secret",
            "registry_pass": "dckr_pat_abc123",
            "api_key": "sk-live-xyz",
            "client_secret": "cs-987",
            "token_budget": 4000,
            "safe_to_store": False,
            "nodes": [
                {"entity_type": "credential", "label": "GITHUB_FINE_GRAINED_TOKEN"},
                {"matched_preview": "[SECRET_REDACTED]"},
            ],
            "mcp": {"env": {"DB_PASSWORD": "pgpass", "HOST": "db.local"}},
        }
    }

    out = json.loads(dumps_envelope(payload))["data"]

    # secret-keyed string values are masked
    assert out["password"] == "[REDACTED]"
    assert out["registry_pass"] == "[REDACTED]"
    assert out["api_key"] == "[REDACTED]"
    assert out["client_secret"] == "[REDACTED]"
    assert out["mcp"]["env"]["DB_PASSWORD"] == "[REDACTED]"

    # non-secret fields and reference labels survive
    assert out["token_budget"] == 4000
    assert out["safe_to_store"] is False
    assert out["mcp"]["env"]["HOST"] == "db.local"
    assert out["nodes"][0]["label"] == "GITHUB_FINE_GRAINED_TOKEN"
    assert out["nodes"][0]["entity_type"] == "credential"


def test_redaction_is_idempotent() -> None:
    once = dumps_envelope({"password": "x"})
    twice = dumps_envelope(json.loads(once))
    assert json.loads(twice)["password"] == "[REDACTED]"
