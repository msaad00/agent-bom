"""Tests for security hardening — input validation, error sanitization, path safety."""

from __future__ import annotations

import pytest

from agent_bom.security import (
    SecurityError,
    sanitize_error,
    validate_command,
    validate_image_ref,
)

# ─── Image Reference Validation ──────────────────────────────────────────────


class TestImageRefValidation:
    """validate_image_ref should reject dangerous references."""

    def test_valid_image_refs(self):
        assert validate_image_ref("ubuntu:latest") == "ubuntu:latest"
        assert validate_image_ref("ghcr.io/org/image:v1.0") == "ghcr.io/org/image:v1.0"
        assert validate_image_ref("nginx:1.25-alpine") == "nginx:1.25-alpine"
        assert validate_image_ref("myregistry.com:5000/app:latest") == "myregistry.com:5000/app:latest"

    def test_rejects_flag_injection(self):
        """References starting with - could be interpreted as flags."""
        with pytest.raises(SecurityError):
            validate_image_ref("-flag=value")
        with pytest.raises(SecurityError):
            validate_image_ref("--rm")

    def test_rejects_empty(self):
        with pytest.raises(SecurityError):
            validate_image_ref("")

    def test_rejects_shell_metacharacters(self):
        with pytest.raises(SecurityError):
            validate_image_ref("image;rm -rf /")
        with pytest.raises(SecurityError):
            validate_image_ref("image$(whoami)")
        with pytest.raises(SecurityError):
            validate_image_ref("image`id`")


# ─── Snowflake Identifier Validation ─────────────────────────────────────────


class TestSnowflakeIdentifierValidation:
    """_validate_sf_identifier should reject SQL injection attempts."""

    def test_valid_identifiers(self):
        from agent_bom.cloud.snowflake import _validate_sf_identifier

        assert _validate_sf_identifier("MY_SERVER") == "MY_SERVER"
        assert _validate_sf_identifier("DB.SCHEMA.SERVER") == "DB.SCHEMA.SERVER"
        assert _validate_sf_identifier("db_name$1") == "db_name$1"

    def test_rejects_sql_injection(self):
        from agent_bom.cloud.snowflake import _validate_sf_identifier

        with pytest.raises(ValueError, match="Unsafe Snowflake identifier"):
            _validate_sf_identifier("; DROP TABLE users --")

        with pytest.raises(ValueError, match="Unsafe Snowflake identifier"):
            _validate_sf_identifier("server; DELETE FROM")

    def test_rejects_comment_injection(self):
        from agent_bom.cloud.snowflake import _validate_sf_identifier

        with pytest.raises(ValueError):
            _validate_sf_identifier("server /* comment */")

    def test_rejects_empty_or_numeric_start(self):
        from agent_bom.cloud.snowflake import _validate_sf_identifier

        with pytest.raises(ValueError):
            _validate_sf_identifier("")
        with pytest.raises(ValueError):
            _validate_sf_identifier("123start")


# ─── Error Sanitization ──────────────────────────────────────────────────────


class TestErrorSanitization:
    """sanitize_error should strip sensitive details."""

    def test_strips_file_paths(self):
        exc = Exception("Failed to read /home/user/.config/agent-bom/config.json")
        result = sanitize_error(exc)
        assert "/home/user" not in result
        assert "<path>" in result

    def test_strips_urls(self):
        exc = Exception("Connection failed to https://api.internal.corp.com:8443/v1/scan")
        result = sanitize_error(exc)
        assert "internal.corp.com" not in result
        assert "<url>" in result

    def test_truncates_long_messages(self):
        exc = Exception("x" * 500)
        result = sanitize_error(exc)
        assert len(result) <= 200

    def test_preserves_safe_messages(self):
        exc = Exception("Invalid package name")
        result = sanitize_error(exc)
        assert result == "Invalid package name"


# ─── Proxy Command Validation ────────────────────────────────────────────────


class TestProxyCommandValidation:
    """Proxy should validate commands before spawning."""

    def test_allowed_commands_accepted(self):
        """npx, uvx, python, etc. should be allowed."""
        for cmd in ["npx", "uvx", "python", "python3", "node", "deno", "bun"]:
            validate_command(cmd)  # Should not raise

    def test_arbitrary_commands_rejected(self):
        """Random executables should be rejected."""
        with pytest.raises(SecurityError):
            validate_command("bash")
        with pytest.raises(SecurityError):
            validate_command("/usr/bin/evil")
        with pytest.raises(SecurityError):
            validate_command("curl")


# ─── Safe Path Validation ────────────────────────────────────────────────────


class TestSafePath:
    """_safe_path should use is_relative_to for robust home dir check."""

    def test_rejects_outside_home(self):
        from agent_bom.mcp_server import _safe_path

        with pytest.raises(ValueError, match="outside home directory"):
            _safe_path("/etc/passwd")

    def test_rejects_traversal(self):
        from agent_bom.mcp_server import _safe_path

        with pytest.raises(ValueError, match="outside home directory"):
            _safe_path("/tmp/../etc/passwd")

    def test_accepts_home_paths(self):
        from pathlib import Path

        from agent_bom.mcp_server import _safe_path

        home = Path.home()
        result = _safe_path(str(home))
        assert result == home
