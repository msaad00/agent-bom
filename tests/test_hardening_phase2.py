"""Tests for Phase 2 production hardening.

Covers:
- config.py expansion (15 new constants, _str() helper, env overrides)
- Audit HMAC ephemeral key (no hardcoded default)
- Exception narrowing (consumer modules use specific types)
- inventory.py (JSON, CSV, stdin, auto-detect, error cases)
"""

from __future__ import annotations

import io
import json
import os
import textwrap
from unittest.mock import patch

import pytest

# ── Config Expansion ────────────────────────────────────────────────────────


class TestConfigDefaults:
    """Verify all 15 new constants have correct defaults."""

    def test_http_max_retries(self):
        from agent_bom.config import HTTP_MAX_RETRIES

        assert HTTP_MAX_RETRIES == 3

    def test_http_initial_backoff(self):
        from agent_bom.config import HTTP_INITIAL_BACKOFF

        assert HTTP_INITIAL_BACKOFF == 1.0

    def test_http_max_backoff(self):
        from agent_bom.config import HTTP_MAX_BACKOFF

        assert HTTP_MAX_BACKOFF == 30.0

    def test_http_default_timeout(self):
        from agent_bom.config import HTTP_DEFAULT_TIMEOUT

        assert HTTP_DEFAULT_TIMEOUT == 30.0

    def test_scanner_max_concurrent(self):
        from agent_bom.config import SCANNER_MAX_CONCURRENT

        assert SCANNER_MAX_CONCURRENT == 10

    def test_scanner_batch_delay(self):
        from agent_bom.config import SCANNER_BATCH_DELAY

        assert SCANNER_BATCH_DELAY == 0.5

    def test_ai_cache_max_entries(self):
        from agent_bom.config import AI_CACHE_MAX_ENTRIES

        assert AI_CACHE_MAX_ENTRIES == 1_000

    def test_ollama_base_url(self):
        from agent_bom.config import OLLAMA_BASE_URL

        assert OLLAMA_BASE_URL == "http://localhost:11434"

    def test_enrichment_ttl_seconds(self):
        from agent_bom.config import ENRICHMENT_TTL_SECONDS

        assert ENRICHMENT_TTL_SECONDS == 604_800

    def test_enrichment_max_cache(self):
        from agent_bom.config import ENRICHMENT_MAX_CACHE_ENTRIES

        assert ENRICHMENT_MAX_CACHE_ENTRIES == 10_000

    def test_api_max_concurrent_jobs(self):
        from agent_bom.config import API_MAX_CONCURRENT_JOBS

        assert API_MAX_CONCURRENT_JOBS == 10

    def test_api_job_ttl_seconds(self):
        from agent_bom.config import API_JOB_TTL_SECONDS

        assert API_JOB_TTL_SECONDS == 3_600

    def test_api_max_in_memory_jobs(self):
        from agent_bom.config import API_MAX_IN_MEMORY_JOBS

        assert API_MAX_IN_MEMORY_JOBS == 200

    def test_mcp_max_file_size(self):
        from agent_bom.config import MCP_MAX_FILE_SIZE

        assert MCP_MAX_FILE_SIZE == 50 * 1024 * 1024

    def test_mcp_max_response_chars(self):
        from agent_bom.config import MCP_MAX_RESPONSE_CHARS

        assert MCP_MAX_RESPONSE_CHARS == 500_000


class TestConfigHelpers:
    """Test _float(), _int(), _str() helpers."""

    def test_str_helper_returns_default(self):
        from agent_bom.config import _str

        assert _str("AGENT_BOM_TEST_NONEXISTENT_KEY_XYZ", "fallback") == "fallback"

    def test_str_helper_reads_env(self):
        from agent_bom.config import _str

        with patch.dict(os.environ, {"AGENT_BOM_TEST_STR_KEY": "custom_val"}):
            assert _str("AGENT_BOM_TEST_STR_KEY", "default") == "custom_val"

    def test_int_helper_returns_default_on_invalid(self):
        from agent_bom.config import _int

        with patch.dict(os.environ, {"AGENT_BOM_TEST_BAD_INT": "not_a_number"}):
            assert _int("AGENT_BOM_TEST_BAD_INT", 42) == 42

    def test_float_helper_returns_default_on_invalid(self):
        from agent_bom.config import _float

        with patch.dict(os.environ, {"AGENT_BOM_TEST_BAD_FLOAT": "xyz"}):
            assert _float("AGENT_BOM_TEST_BAD_FLOAT", 3.14) == 3.14


class TestConfigConsumerImports:
    """Verify consumer modules import from config (not hardcoded)."""

    def test_http_client_uses_config_retries(self):
        from agent_bom import config
        from agent_bom.http_client import MAX_RETRIES

        assert MAX_RETRIES == config.HTTP_MAX_RETRIES

    def test_http_client_uses_config_backoff(self):
        from agent_bom import config
        from agent_bom.http_client import INITIAL_BACKOFF, MAX_BACKOFF

        assert INITIAL_BACKOFF == config.HTTP_INITIAL_BACKOFF
        assert MAX_BACKOFF == config.HTTP_MAX_BACKOFF

    def test_scanners_uses_config_concurrency(self):
        from agent_bom import config
        from agent_bom.scanners import BATCH_DELAY_SECONDS, MAX_CONCURRENT_REQUESTS

        assert MAX_CONCURRENT_REQUESTS == config.SCANNER_MAX_CONCURRENT
        assert BATCH_DELAY_SECONDS == config.SCANNER_BATCH_DELAY


# ── Audit HMAC ──────────────────────────────────────────────────────────────


class TestAuditHMAC:
    """Verify HMAC key is ephemeral (no hardcoded default)."""

    def test_no_hardcoded_hmac_default_in_source(self):
        """Source code must NOT contain a static HMAC key string."""
        import inspect

        from agent_bom.api import audit_log

        source = inspect.getsource(audit_log)
        assert "agent-bom-default-audit-key" not in source

    def test_ephemeral_key_is_bytes(self):
        from agent_bom.api.audit_log import _HMAC_KEY

        assert isinstance(_HMAC_KEY, bytes)
        assert len(_HMAC_KEY) >= 16  # At least 128-bit

    def test_sign_verify_roundtrip(self):
        from agent_bom.api.audit_log import AuditEntry

        entry = AuditEntry(action="scan", actor="test", resource="job/test-1")
        entry.sign()
        assert entry.hmac_signature
        assert entry.verify()

    def test_tampered_entry_fails_verify(self):
        from agent_bom.api.audit_log import AuditEntry

        entry = AuditEntry(action="scan", actor="test", resource="job/test-1")
        entry.sign()
        entry.action = "tampered"
        assert not entry.verify()

    def test_in_memory_log_signs_on_append(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        entry = AuditEntry(action="test_action", actor="ci")
        assert entry.hmac_signature == ""
        log.append(entry)
        assert entry.hmac_signature != ""
        assert entry.verify()

    def test_in_memory_integrity_check(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        for i in range(5):
            log.append(AuditEntry(action="scan", actor=f"user-{i}"))
        verified, tampered = log.verify_integrity()
        assert verified == 5
        assert tampered == 0

    def test_env_var_hmac_key_used(self):
        """When AGENT_BOM_AUDIT_HMAC_KEY is set, it should be used."""
        import importlib

        from agent_bom.api import audit_log

        with patch.dict(os.environ, {"AGENT_BOM_AUDIT_HMAC_KEY": "test-secret-key-42"}):
            importlib.reload(audit_log)
            assert audit_log._HMAC_KEY == b"test-secret-key-42"

        # Reload again without env var to restore ephemeral key
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_BOM_AUDIT_HMAC_KEY", None)
            os.environ.pop("AGENT_BOM_REQUIRE_AUDIT_HMAC", None)
            importlib.reload(audit_log)
            assert isinstance(audit_log._HMAC_KEY, bytes)

    def test_require_audit_hmac_fails_closed(self):
        """When production enforcement is enabled, missing HMAC key should fail closed."""
        import importlib

        from agent_bom.api import audit_log

        with patch.dict(
            os.environ,
            {"AGENT_BOM_REQUIRE_AUDIT_HMAC": "1"},
            clear=False,
        ):
            os.environ.pop("AGENT_BOM_AUDIT_HMAC_KEY", None)
            with pytest.raises(RuntimeError, match="AGENT_BOM_REQUIRE_AUDIT_HMAC"):
                importlib.reload(audit_log)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENT_BOM_AUDIT_HMAC_KEY", None)
            os.environ.pop("AGENT_BOM_REQUIRE_AUDIT_HMAC", None)
            importlib.reload(audit_log)


# ── Exception Narrowing ────────────────────────────────────────────────────


class TestExceptionNarrowing:
    """Verify critical except clauses use specific types."""

    def test_http_client_url_sanitizer_catches_value_error(self):
        from agent_bom.http_client import _safe_url

        # Should not raise — handles ValueError/AttributeError gracefully
        result = _safe_url("not://a[valid/url")
        assert isinstance(result, str)

    def test_enrichment_cache_handles_corrupt_json(self, tmp_path):
        """Enrichment cache load should handle corrupt JSON gracefully."""
        import agent_bom.enrichment as enrich_mod

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        (cache_dir / "nvd_cache.json").write_text("this is not json{{{")

        # Temporarily swap cache dir and reset loaded flag
        orig_dir = enrich_mod._ENRICHMENT_CACHE_DIR
        orig_loaded = enrich_mod._enrichment_cache_loaded
        try:
            enrich_mod._ENRICHMENT_CACHE_DIR = cache_dir
            enrich_mod._enrichment_cache_loaded = False
            # Should not raise — the narrowed except handles it
            enrich_mod._load_enrichment_cache()
        finally:
            enrich_mod._ENRICHMENT_CACHE_DIR = orig_dir
            enrich_mod._enrichment_cache_loaded = orig_loaded

    def test_registry_handles_corrupt_json(self, tmp_path):
        """Registry _load_registry should handle corrupt JSON files."""
        from agent_bom.registry import _load_registry

        bad_file = tmp_path / "registry.json"
        bad_file.write_text("{corrupt json!!")

        with patch.object(
            __import__("agent_bom.registry", fromlist=["_REGISTRY_PATH"]),
            "_REGISTRY_PATH",
            bad_file,
        ):
            result = _load_registry()
            assert result == {}

    def test_push_imports_httpx(self):
        """push.py should import httpx at module level for exception handling."""
        import agent_bom.push as push_mod

        assert hasattr(push_mod, "httpx")


# ── Inventory Module ────────────────────────────────────────────────────────


class TestInventoryDetectFormat:
    """Test auto-detection of JSON vs CSV content."""

    def test_detect_json_object(self):
        from agent_bom.inventory import _detect_format

        assert _detect_format('{"agents": []}') == "json"

    def test_detect_json_array(self):
        from agent_bom.inventory import _detect_format

        assert _detect_format("[1, 2, 3]") == "json"

    def test_detect_json_with_whitespace(self):
        from agent_bom.inventory import _detect_format

        assert _detect_format("  \n  { }") == "json"

    def test_detect_csv(self):
        from agent_bom.inventory import _detect_format

        assert _detect_format("name,version,ecosystem\n") == "csv"

    def test_detect_csv_plain_text(self):
        from agent_bom.inventory import _detect_format

        assert _detect_format("some,data,here") == "csv"


class TestInventoryCSV:
    """Test CSV inventory loading."""

    def test_minimal_3_column_csv(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "name,version,ecosystem\nlangchain,0.1.0,pypi\nfastapi,0.104.0,pypi\n"
        result = _load_csv_inventory(io.StringIO(csv_data))

        assert "agents" in result
        agents = result["agents"]
        assert len(agents) == 1
        agent = agents[0]
        assert agent["name"] == "inventory-agent"
        assert len(agent["mcp_servers"]) == 1
        server = agent["mcp_servers"][0]
        assert server["name"] == "inventory-server"
        assert len(server["packages"]) == 2

    def test_full_column_csv(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = textwrap.dedent("""\
            name,version,ecosystem,server_name,agent_name,env_keys
            langchain,0.1.0,pypi,ai-server,prod-agent,OPENAI_API_KEY;SLACK_TOKEN
            express,4.18.2,npm,api-server,prod-agent,
            fastapi,0.104.0,pypi,ai-server,prod-agent,
        """)
        result = _load_csv_inventory(io.StringIO(csv_data))

        agents = result["agents"]
        assert len(agents) == 1
        agent = agents[0]
        assert agent["name"] == "prod-agent"
        # Two servers: ai-server and api-server
        server_names = {s["name"] for s in agent["mcp_servers"]}
        assert server_names == {"ai-server", "api-server"}

    def test_agent_server_grouping(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = textwrap.dedent("""\
            name,version,ecosystem,agent_name,server_name
            pkg-a,1.0,pypi,agent-1,server-1
            pkg-b,2.0,npm,agent-2,server-2
        """)
        result = _load_csv_inventory(io.StringIO(csv_data))

        agents = result["agents"]
        assert len(agents) == 2
        agent_names = {a["name"] for a in agents}
        assert agent_names == {"agent-1", "agent-2"}

    def test_default_agent_server_names(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "name,version,ecosystem\nfoo,1.0,pip\n"
        result = _load_csv_inventory(io.StringIO(csv_data))

        agent = result["agents"][0]
        assert agent["name"] == "inventory-agent"
        assert agent["mcp_servers"][0]["name"] == "inventory-server"

    def test_env_keys_parsed(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "name,version,ecosystem,env_keys\nfoo,1.0,pypi,API_KEY;SECRET\n"
        result = _load_csv_inventory(io.StringIO(csv_data))

        env = result["agents"][0]["mcp_servers"][0]["env"]
        assert env == {"API_KEY": "REDACTED", "SECRET": "REDACTED"}

    def test_missing_required_columns_raises(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "name,version\nfoo,1.0\n"
        with pytest.raises(ValueError, match="missing required columns"):
            _load_csv_inventory(io.StringIO(csv_data))

    def test_empty_csv_raises(self):
        from agent_bom.inventory import _load_csv_inventory

        with pytest.raises(ValueError, match="empty"):
            _load_csv_inventory(io.StringIO(""))

    def test_rows_with_empty_name_skipped(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "name,version,ecosystem\n,1.0,pypi\nfoo,2.0,pypi\n"
        result = _load_csv_inventory(io.StringIO(csv_data))
        pkgs = result["agents"][0]["mcp_servers"][0]["packages"]
        assert len(pkgs) == 1
        assert pkgs[0]["name"] == "foo"

    def test_ecosystem_defaults_to_unknown(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "name,version,ecosystem\nfoo,1.0,\n"
        result = _load_csv_inventory(io.StringIO(csv_data))
        pkg = result["agents"][0]["mcp_servers"][0]["packages"][0]
        assert pkg["ecosystem"] == "unknown"

    def test_case_insensitive_headers(self):
        from agent_bom.inventory import _load_csv_inventory

        csv_data = "Name, Version, Ecosystem\nfoo,1.0,pypi\n"
        result = _load_csv_inventory(io.StringIO(csv_data))
        assert len(result["agents"]) == 1


class TestInventoryJSON:
    """Test JSON inventory loading."""

    def test_json_file_loading(self, tmp_path):
        from agent_bom.inventory import load_inventory

        data = {"agents": [{"name": "test", "mcp_servers": []}]}
        json_file = tmp_path / "inventory.json"
        json_file.write_text(json.dumps(data))

        result = load_inventory(str(json_file))
        assert result == data

    def test_csv_file_detected_by_extension(self, tmp_path):
        from agent_bom.inventory import load_inventory

        csv_file = tmp_path / "inventory.csv"
        csv_file.write_text("name,version,ecosystem\nfoo,1.0,pypi\n")

        result = load_inventory(str(csv_file))
        assert "agents" in result
        assert len(result["agents"]) == 1


class TestInventoryFileErrors:
    """Test error handling for file loading."""

    def test_file_not_found(self):
        from agent_bom.inventory import load_inventory

        with pytest.raises(FileNotFoundError, match="not found"):
            load_inventory("/nonexistent/path/inventory.json")


class TestInventoryStdin:
    """Test stdin inventory loading."""

    def test_stdin_json(self):
        from agent_bom.inventory import _load_from_stdin

        data = json.dumps({"agents": [{"name": "stdin-agent", "mcp_servers": []}]})
        with patch("sys.stdin", io.StringIO(data)):
            result = _load_from_stdin()
        assert result["agents"][0]["name"] == "stdin-agent"

    def test_stdin_csv(self):
        from agent_bom.inventory import _load_from_stdin

        csv_data = "name,version,ecosystem\nfoo,1.0,pypi\n"
        with patch("sys.stdin", io.StringIO(csv_data)):
            result = _load_from_stdin()
        assert "agents" in result

    def test_stdin_empty_raises(self):
        from agent_bom.inventory import _load_from_stdin

        with patch("sys.stdin", io.StringIO("   ")):
            with pytest.raises(ValueError, match="Empty input"):
                _load_from_stdin()
