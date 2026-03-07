"""Tests for cloud/vector_db.py — vector database discovery and security checks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from agent_bom.cloud.vector_db import (
    MAESTRO_LAYER,
    VECTOR_DB_PORTS,
    VectorDBResult,
    _count_collections,
    _is_loopback,
    _parse_version,
    check_vector_db,
    discover_vector_dbs,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_vector_db_ports_coverage():
    assert "qdrant" in VECTOR_DB_PORTS
    assert "weaviate" in VECTOR_DB_PORTS
    assert "chroma" in VECTOR_DB_PORTS
    assert "milvus" in VECTOR_DB_PORTS
    assert VECTOR_DB_PORTS["qdrant"] == 6333
    assert VECTOR_DB_PORTS["weaviate"] == 8080
    assert VECTOR_DB_PORTS["chroma"] == 8000


def test_maestro_layer_is_kc4():
    assert MAESTRO_LAYER == "KC4: Memory & Context"


# ---------------------------------------------------------------------------
# VectorDBResult model
# ---------------------------------------------------------------------------


def _make_result(**kwargs) -> VectorDBResult:
    defaults = dict(
        db_type="qdrant",
        host="127.0.0.1",
        port=6333,
        is_reachable=True,
        requires_auth=True,
        version="1.7.4",
        collection_count=0,
        is_loopback=True,
        risk_flags=[],
    )
    defaults.update(kwargs)
    return VectorDBResult(**defaults)


def test_risk_level_safe():
    r = _make_result(requires_auth=True, is_loopback=True)
    assert r.risk_level == "safe"


def test_risk_level_safe_with_flags():
    r = _make_result(requires_auth=True, is_loopback=True, risk_flags=["no_tls"])
    assert r.risk_level == "medium"


def test_risk_level_high_no_auth_localhost():
    r = _make_result(requires_auth=False, is_loopback=True)
    assert r.risk_level == "high"


def test_risk_level_critical_no_auth_network_exposed():
    r = _make_result(requires_auth=False, is_loopback=False)
    assert r.risk_level == "critical"


def test_to_dict_has_required_keys():
    d = _make_result().to_dict()
    for key in (
        "db_type",
        "host",
        "port",
        "is_reachable",
        "requires_auth",
        "version",
        "collection_count",
        "is_loopback",
        "risk_level",
        "risk_flags",
        "maestro_layer",
        "metadata",
    ):
        assert key in d, f"Missing key: {key}"


def test_to_dict_maestro_layer():
    d = _make_result().to_dict()
    assert d["maestro_layer"] == "KC4: Memory & Context"


def test_to_dict_values_correct():
    r = _make_result(db_type="weaviate", port=8080, requires_auth=False)
    d = r.to_dict()
    assert d["db_type"] == "weaviate"
    assert d["port"] == 8080
    assert d["requires_auth"] is False


# ---------------------------------------------------------------------------
# _is_loopback
# ---------------------------------------------------------------------------


def test_is_loopback_localhost():
    assert _is_loopback("127.0.0.1") is True
    assert _is_loopback("localhost") is True


def test_is_loopback_external_ip():
    assert _is_loopback("8.8.8.8") is False


def test_is_loopback_invalid_returns_false():
    assert _is_loopback("not-a-valid-host-xyz-12345.local") is False


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------


def test_parse_version_qdrant():
    body = b'{"version": "1.7.4"}'
    assert _parse_version("qdrant", body) == "1.7.4"


def test_parse_version_weaviate():
    body = b'{"version": "1.24.0"}'
    assert _parse_version("weaviate", body) == "1.24.0"


def test_parse_version_chroma():
    body = b'{"version": "0.4.22"}'
    assert _parse_version("chroma", body) == "0.4.22"


def test_parse_version_invalid_json():
    assert _parse_version("qdrant", b"not json") == ""


def test_parse_version_missing_field():
    assert _parse_version("qdrant", b"{}") == ""


# ---------------------------------------------------------------------------
# _count_collections
# ---------------------------------------------------------------------------


def test_count_collections_qdrant():
    import json

    body = json.dumps({"result": {"collections": [{"name": "a"}, {"name": "b"}]}}).encode()
    assert _count_collections("qdrant", body) == 2


def test_count_collections_weaviate():
    import json

    body = json.dumps({"classes": [{"class": "Article"}, {"class": "Author"}]}).encode()
    assert _count_collections("weaviate", body) == 2


def test_count_collections_chroma():
    import json

    body = json.dumps([{"id": "abc"}, {"id": "def"}]).encode()
    assert _count_collections("chroma", body) == 2


def test_count_collections_milvus():
    import json

    body = json.dumps({"data": ["col1", "col2", "col3"]}).encode()
    assert _count_collections("milvus", body) == 3


def test_count_collections_empty():
    import json

    assert _count_collections("qdrant", json.dumps({"result": {"collections": []}}).encode()) == 0


def test_count_collections_invalid_json():
    assert _count_collections("qdrant", b"bad json") == 0


# ---------------------------------------------------------------------------
# check_vector_db — port closed (not running)
# ---------------------------------------------------------------------------


def test_check_vector_db_not_running():
    with patch("agent_bom.cloud.vector_db._port_open", return_value=False):
        result = check_vector_db("qdrant", host="127.0.0.1")
    assert result.is_reachable is False
    assert result.requires_auth is True  # assume auth when not reachable
    assert result.risk_flags == []


def test_check_vector_db_unknown_db_type():
    result = check_vector_db("unknowndb", host="127.0.0.1")
    assert result.is_reachable is False
    assert "error" in result.metadata


# ---------------------------------------------------------------------------
# check_vector_db — port open, no auth
# ---------------------------------------------------------------------------


def test_check_vector_db_no_auth():
    import json as _json

    collections_body = _json.dumps({"result": {"collections": [{"name": "test"}]}}).encode()

    def fake_port_open(host, port, timeout=3):
        return True

    def fake_http_get(host, port, path, timeout=3):
        if path == "/collections":
            return 200, collections_body
        return 200, b'{"version": "1.7.4"}'

    with (
        patch("agent_bom.cloud.vector_db._port_open", side_effect=fake_port_open),
        patch("agent_bom.cloud.vector_db._http_get", side_effect=fake_http_get),
        patch("agent_bom.cloud.vector_db._is_loopback", return_value=True),
    ):
        result = check_vector_db("qdrant", host="127.0.0.1")

    assert result.is_reachable is True
    assert result.requires_auth is False
    assert "no_auth" in result.risk_flags
    assert result.collection_count == 1
    assert "collections_exposed" in result.risk_flags


def test_check_vector_db_auth_enforced():
    def fake_port_open(host, port, timeout=3):
        return True

    def fake_http_get(host, port, path, timeout=3):
        if path == "/collections":
            return 401, b""
        return 200, b'{"version": "1.7.4"}'

    with (
        patch("agent_bom.cloud.vector_db._port_open", side_effect=fake_port_open),
        patch("agent_bom.cloud.vector_db._http_get", side_effect=fake_http_get),
        patch("agent_bom.cloud.vector_db._is_loopback", return_value=True),
    ):
        result = check_vector_db("qdrant", host="127.0.0.1")

    assert result.is_reachable is True
    assert result.requires_auth is True
    assert "no_auth" not in result.risk_flags


def test_check_vector_db_network_exposed():
    def fake_port_open(host, port, timeout=3):
        return True  # Reachable on both localhost and network IP

    def fake_http_get(host, port, path, timeout=3):
        if path == "/collections":
            return 401, b""
        return 200, b"{}"

    def fake_socket_context():
        mock = MagicMock()
        mock.__enter__ = MagicMock(return_value=mock)
        mock.__exit__ = MagicMock(return_value=False)
        mock.getsockname.return_value = ("192.168.1.100", 0)
        return mock

    with (
        patch("agent_bom.cloud.vector_db._port_open", side_effect=fake_port_open),
        patch("agent_bom.cloud.vector_db._http_get", side_effect=fake_http_get),
        patch("agent_bom.cloud.vector_db._is_loopback", return_value=True),
        patch("socket.socket", return_value=fake_socket_context()),
    ):
        result = check_vector_db("qdrant", host="127.0.0.1")

    assert result.is_reachable is True
    assert "network_exposed" in result.risk_flags
    assert result.is_loopback is False


# ---------------------------------------------------------------------------
# discover_vector_dbs
# ---------------------------------------------------------------------------


def test_discover_vector_dbs_none_running():
    with patch("agent_bom.cloud.vector_db._port_open", return_value=False):
        results = discover_vector_dbs()
    assert results == []


def test_discover_vector_dbs_one_running():
    def fake_port_open(host, port, timeout=3):
        return port == 6333  # Only Qdrant running

    def fake_http_get(host, port, path, timeout=3):
        if path == "/collections":
            return 401, b""
        return 200, b'{"version": "1.7.4"}'

    with (
        patch("agent_bom.cloud.vector_db._port_open", side_effect=fake_port_open),
        patch("agent_bom.cloud.vector_db._http_get", side_effect=fake_http_get),
        patch("agent_bom.cloud.vector_db._is_loopback", return_value=True),
    ):
        results = discover_vector_dbs(hosts=["127.0.0.1"])

    assert len(results) == 1
    assert results[0].db_type == "qdrant"
    assert results[0].port == 6333


def test_discover_vector_dbs_deduplicates():
    """localhost and 127.0.0.1 should not double-count the same port."""
    with patch("agent_bom.cloud.vector_db._port_open", return_value=False):
        results = discover_vector_dbs(hosts=["127.0.0.1", "localhost"])
    assert results == []
