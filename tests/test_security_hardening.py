"""Tests for security hardening — input validation, error sanitization, path safety."""

from __future__ import annotations

import base64 as _base64

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


class TestSnowflakeQuotedIdentifier:
    """Quoted identifiers should be escaped safely for SQL interpolation."""

    def test_quotes_plain_identifier(self):
        from agent_bom.cloud.snowflake import _quote_sf_identifier

        assert _quote_sf_identifier("NOTEBOOK_ONE") == '"NOTEBOOK_ONE"'

    def test_escapes_embedded_quotes(self):
        from agent_bom.cloud.snowflake import _quote_sf_identifier

        assert _quote_sf_identifier('weird"name') == '"weird""name"'

    def test_rejects_control_characters(self):
        from agent_bom.cloud.snowflake import _quote_sf_identifier

        with pytest.raises(ValueError):
            _quote_sf_identifier("bad\nname")


class TestSnowflakeDaysValidation:
    """Snowflake day windows should be normalized before SQL interpolation."""

    def test_accepts_positive_int_like_values(self):
        from agent_bom.cloud.snowflake import _coerce_snowflake_days

        assert _coerce_snowflake_days("7") == 7
        assert _coerce_snowflake_days(30, max_days=365) == 30

    def test_rejects_non_integer_values(self):
        from agent_bom.cloud.snowflake import _coerce_snowflake_days

        with pytest.raises(ValueError, match="days must be an integer"):
            _coerce_snowflake_days("7; DROP TABLE")

    def test_rejects_zero_or_negative_values(self):
        from agent_bom.cloud.snowflake import _coerce_snowflake_days

        with pytest.raises(ValueError, match="days must be >= 1"):
            _coerce_snowflake_days(0)
        with pytest.raises(ValueError, match="days must be >= 1"):
            _coerce_snowflake_days(-5)

    def test_caps_values_when_max_days_is_provided(self):
        from agent_bom.cloud.snowflake import _coerce_snowflake_days

        assert _coerce_snowflake_days(999, max_days=365) == 365


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


# ─── Obfuscated / base64 credential detection (#405) ──────────────────────────


class TestObfuscatedCredentialDetection:
    """sanitize_env_vars must catch base64-encoded and high-entropy secrets."""

    def _b64(self, s: str) -> str:
        return _base64.b64encode(s.encode()).decode()

    def test_base64_encoded_api_key_value_redacted(self):
        from agent_bom.security import sanitize_env_vars

        # Value contains "api_key=supersecret" base64-encoded
        encoded = self._b64("api_key=supersecret_value_here")
        result = sanitize_env_vars({"CUSTOM_VAR": encoded})
        assert result["CUSTOM_VAR"] == "***REDACTED***"

    def test_base64_encoded_password_keyword_redacted(self):
        from agent_bom.security import sanitize_env_vars

        encoded = self._b64("password=my_super_secret_pass")
        result = sanitize_env_vars({"DATA": encoded})
        assert result["DATA"] == "***REDACTED***"

    def test_base64_encoded_github_token_redacted(self):
        from agent_bom.security import sanitize_env_vars

        token = "ghp_" + "A" * 36
        encoded = self._b64(token)
        result = sanitize_env_vars({"ENCODED_TOKEN": encoded})
        assert result["ENCODED_TOKEN"] == "***REDACTED***"

    def test_high_entropy_long_string_redacted(self):
        # Simulate a raw 40-char base64url token (high entropy, no spaces)
        import secrets as _secrets

        from agent_bom.security import sanitize_env_vars

        high_entropy = _secrets.token_urlsafe(40)  # ~54 chars, entropy ≈ 6.0
        result = sanitize_env_vars({"MY_CUSTOM_KEY": high_entropy})
        assert result["MY_CUSTOM_KEY"] == "***REDACTED***"

    def test_plaintext_url_not_redacted(self):
        from agent_bom.security import sanitize_env_vars

        # A URL with path should not be flagged even if high-entropy
        result = sanitize_env_vars({"ENDPOINT": "https://api.example.com/v1/data"})
        assert result["ENDPOINT"] == "https://api.example.com/v1/data"

    def test_short_base64_not_flagged(self):
        from agent_bom.security import sanitize_env_vars

        # Short base64 values are not secrets (too short to be meaningful)
        result = sanitize_env_vars({"VALUE": "dGVzdA=="})  # "test" in base64
        assert result["VALUE"] == "dGVzdA=="

    def test_normal_string_not_redacted(self):
        from agent_bom.security import sanitize_env_vars

        result = sanitize_env_vars({"PATH_VAR": "/usr/local/bin:/usr/bin"})
        assert result["PATH_VAR"] == "/usr/local/bin:/usr/bin"

    def test_shannon_entropy_helper(self):
        from agent_bom.security import _shannon_entropy

        # Uniform distribution has high entropy
        high = _shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789ABCDE")
        # Repeated char has zero entropy
        low = _shannon_entropy("aaaaaaaaaaaa")
        assert high > 4.0
        assert low == 0.0
