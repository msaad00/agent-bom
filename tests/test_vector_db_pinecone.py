"""Tests for Pinecone cloud vector DB scanning (closes #310).

Tests cover:
- check_pinecone() raises ValueError on empty API key
- check_pinecone() returns empty list on 401 (invalid key)
- check_pinecone() returns empty list on 403 (insufficient permission)
- check_pinecone() returns empty list when index list is empty
- check_pinecone() parses pod-based index correctly
- check_pinecone() parses serverless index correctly
- check_pinecone() sets high_replica_count risk flag when replicas > 10
- PineconeIndexResult.risk_level == "safe" with no flags
- PineconeIndexResult.risk_level == "medium" with flags
- PineconeIndexResult.to_dict() has required keys
- discover_pinecone() returns [] when PINECONE_API_KEY not set
- discover_pinecone() calls check_pinecone() when key is set
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from agent_bom.cloud.vector_db import (
    PineconeIndexResult,
    check_pinecone,
    discover_pinecone,
)

# ── Helpers ────────────────────────────────────────────────────────────────────


def _pod_index(name: str, replicas: int = 1) -> dict:
    return {
        "name": name,
        "dimension": 1536,
        "metric": "cosine",
        "spec": {
            "pod": {
                "environment": "us-east1-gcp",
                "pod_type": "p1.x1",
                "pods": 1,
                "replicas": replicas,
            }
        },
        "status": {"state": "Ready", "ready": True},
    }


def _serverless_index(name: str) -> dict:
    return {
        "name": name,
        "dimension": 768,
        "metric": "dotproduct",
        "spec": {"serverless": {"cloud": "aws", "region": "us-east-1"}},
        "status": {"state": "Ready", "ready": True},
    }


def _fake_pinecone_get(index_list: list[dict]):
    def _get(path: str, api_key: str, timeout: int = 3) -> tuple[int, dict]:
        return 200, {"indexes": index_list}

    return _get


# ── check_pinecone ─────────────────────────────────────────────────────────────


def test_raises_value_error_on_empty_api_key():
    with pytest.raises(ValueError, match="api_key is required"):
        check_pinecone("")


def test_returns_empty_on_401():
    with patch("agent_bom.cloud.vector_db._pinecone_get", return_value=(401, {})):
        result = check_pinecone("bad-key")
    assert result == []


def test_returns_empty_on_403():
    with patch("agent_bom.cloud.vector_db._pinecone_get", return_value=(403, {})):
        result = check_pinecone("no-permission-key")
    assert result == []


def test_returns_empty_when_no_indexes():
    with patch("agent_bom.cloud.vector_db._pinecone_get", return_value=(200, {"indexes": []})):
        result = check_pinecone("valid-key")
    assert result == []


def test_parses_pod_index():
    indexes = [_pod_index("my-index")]
    with patch("agent_bom.cloud.vector_db._pinecone_get", _fake_pinecone_get(indexes)):
        results = check_pinecone("valid-key")

    assert len(results) == 1
    r = results[0]
    assert r.index_name == "my-index"
    assert r.environment == "us-east1-gcp"
    assert r.dimension == 1536
    assert r.metric == "cosine"
    assert r.pod_type == "p1.x1"
    assert r.replicas == 1
    assert r.is_ready is True
    assert r.risk_flags == []


def test_parses_serverless_index():
    indexes = [_serverless_index("serverless-idx")]
    with patch("agent_bom.cloud.vector_db._pinecone_get", _fake_pinecone_get(indexes)):
        results = check_pinecone("valid-key")

    assert len(results) == 1
    r = results[0]
    assert r.index_name == "serverless-idx"
    assert r.environment == "us-east-1"
    assert r.dimension == 768
    assert r.pod_type == "serverless"


def test_high_replica_count_flag():
    indexes = [_pod_index("big-index", replicas=15)]
    with patch("agent_bom.cloud.vector_db._pinecone_get", _fake_pinecone_get(indexes)):
        results = check_pinecone("key")

    assert "high_replica_count" in results[0].risk_flags


def test_multiple_indexes():
    indexes = [_pod_index("idx-a"), _serverless_index("idx-b"), _pod_index("idx-c")]
    with patch("agent_bom.cloud.vector_db._pinecone_get", _fake_pinecone_get(indexes)):
        results = check_pinecone("key")

    assert len(results) == 3
    names = {r.index_name for r in results}
    assert names == {"idx-a", "idx-b", "idx-c"}


def test_network_failure_returns_empty():
    with patch("agent_bom.cloud.vector_db._pinecone_get", return_value=(-1, {})):
        result = check_pinecone("key")
    assert result == []


# ── PineconeIndexResult ────────────────────────────────────────────────────────


def test_risk_level_safe():
    r = PineconeIndexResult(
        index_name="x",
        environment="us-east",
        dimension=128,
        metric="cosine",
        status="Ready",
        pod_type="p1.x1",
        pods=1,
        replicas=1,
        is_ready=True,
        risk_flags=[],
    )
    assert r.risk_level == "safe"


def test_risk_level_medium_with_flags():
    r = PineconeIndexResult(
        index_name="x",
        environment="us-east",
        dimension=128,
        metric="cosine",
        status="Ready",
        pod_type="p1.x1",
        pods=1,
        replicas=20,
        is_ready=True,
        risk_flags=["high_replica_count"],
    )
    assert r.risk_level == "medium"


def test_to_dict_required_keys():
    r = PineconeIndexResult(
        index_name="test",
        environment="eu-west",
        dimension=512,
        metric="euclidean",
        status="Initializing",
        pod_type="s1.x1",
        pods=2,
        replicas=2,
        is_ready=False,
        risk_flags=[],
    )
    d = r.to_dict()
    assert d["db_type"] == "pinecone"
    assert d["index_name"] == "test"
    assert d["maestro_layer"] == "KC4: Memory & Context"
    assert "risk_level" in d
    assert "risk_flags" in d


# ── discover_pinecone ─────────────────────────────────────────────────────────


def test_discover_returns_empty_when_no_env_key():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("PINECONE_API_KEY", None)
        result = discover_pinecone()
    assert result == []


def test_discover_calls_check_pinecone_with_key():
    mock_result = PineconeIndexResult(
        index_name="env-idx",
        environment="us-east",
        dimension=128,
        metric="cosine",
        status="Ready",
        pod_type="s1.x1",
        pods=1,
        replicas=1,
        is_ready=True,
    )
    with patch.dict(os.environ, {"PINECONE_API_KEY": "sk-test-key"}):
        with patch("agent_bom.cloud.vector_db.check_pinecone", return_value=[mock_result]) as mock_check:
            result = discover_pinecone()

    mock_check.assert_called_once_with("sk-test-key", timeout=3)
    assert len(result) == 1
    assert result[0].index_name == "env-idx"
