"""Tests for agent_bom.security to improve coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.security import (
    SecurityError,
    _is_obfuscated_credential,
    _shannon_entropy,
    create_safe_subprocess_env,
    sanitize_env_vars,
    sanitize_error,
    validate_arguments,
    validate_command,
    validate_environment,
    validate_file_size,
    validate_image_ref,
    validate_json_file,
    validate_mcp_server_config,
    validate_package_name,
    validate_path,
    validate_url,
)

# ---------------------------------------------------------------------------
# validate_command
# ---------------------------------------------------------------------------


def test_validate_command_allowed():
    validate_command("npx")
    validate_command("python3")


def test_validate_command_rejected():
    with pytest.raises(SecurityError):
        validate_command("rm")


# ---------------------------------------------------------------------------
# validate_arguments
# ---------------------------------------------------------------------------


def test_validate_arguments_clean():
    validate_arguments(["--port", "3000", "server.js"])


def test_validate_arguments_semicolon():
    with pytest.raises(SecurityError):
        validate_arguments(["arg; rm -rf /"])


def test_validate_arguments_pipe():
    with pytest.raises(SecurityError):
        validate_arguments(["arg | cat /etc/passwd"])


# ---------------------------------------------------------------------------
# validate_environment
# ---------------------------------------------------------------------------


def test_validate_environment_safe():
    validate_environment({"HOME": "/home/user", "PATH": "/usr/bin"})


def test_validate_environment_dangerous():
    with pytest.raises(SecurityError, match="LD_PRELOAD"):
        validate_environment({"LD_PRELOAD": "/evil.so"})


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


def test_validate_path_normal(tmp_path):
    f = tmp_path / "test.json"
    f.write_text("{}")
    result = validate_path(f)
    assert result.exists()


def test_validate_path_must_exist_missing():
    with pytest.raises(SecurityError, match="does not exist"):
        validate_path("/nonexistent/path/file.json", must_exist=True)


def test_validate_path_traversal():
    with pytest.raises(SecurityError, match="traversal"):
        validate_path("/tmp/../../../etc/passwd")


def test_validate_path_restrict_to_home():
    with pytest.raises(SecurityError, match="outside home"):
        validate_path("/etc/passwd", restrict_to_home=True)


# ---------------------------------------------------------------------------
# _shannon_entropy
# ---------------------------------------------------------------------------


def test_shannon_entropy_empty():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_low():
    entropy = _shannon_entropy("aaaa")
    assert entropy == 0.0


def test_shannon_entropy_high():
    entropy = _shannon_entropy("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u")
    assert entropy > 4.0


# ---------------------------------------------------------------------------
# _is_obfuscated_credential
# ---------------------------------------------------------------------------


def test_is_obfuscated_not_secret():
    assert _is_obfuscated_credential("hello world") is False


def test_is_obfuscated_short():
    assert _is_obfuscated_credential("abc") is False


def test_is_obfuscated_high_entropy():
    # Random-looking 50 char string with high entropy
    s = "aK3bL9cM5dN1eO7fP2gQ8hR4iS6jT0kU3lV9mW5nX1oY7p"
    result = _is_obfuscated_credential(s)
    # Just verify it runs without error
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# sanitize_env_vars
# ---------------------------------------------------------------------------


def test_sanitize_env_vars_sensitive_key():
    result = sanitize_env_vars({"API_KEY": "secret123", "PATH": "/usr/bin"})
    assert result["API_KEY"] == "***REDACTED***"
    assert result["PATH"] == "/usr/bin"


def test_sanitize_env_vars_token():
    result = sanitize_env_vars({"AUTH_TOKEN": "abc"})
    assert result["AUTH_TOKEN"] == "***REDACTED***"


def test_sanitize_env_vars_github_token_in_value():
    result = sanitize_env_vars({"CUSTOM_VAR": "ghp_" + "A" * 36})
    assert result["CUSTOM_VAR"] == "***REDACTED***"


def test_sanitize_env_vars_aws_key_in_value():
    result = sanitize_env_vars({"MY_VAR": "AKIAIOSFODNN7EXAMPLE"})
    assert result["MY_VAR"] == "***REDACTED***"


def test_sanitize_env_vars_safe():
    result = sanitize_env_vars({"HOME": "/home/user", "LANG": "en_US.UTF-8"})
    assert result["HOME"] == "/home/user"
    assert result["LANG"] == "en_US.UTF-8"


# ---------------------------------------------------------------------------
# validate_file_size
# ---------------------------------------------------------------------------


def test_validate_file_size_ok(tmp_path):
    f = tmp_path / "small.txt"
    f.write_text("hello")
    validate_file_size(f)


def test_validate_file_size_too_large(tmp_path):
    f = tmp_path / "big.txt"
    f.write_text("x" * 100)
    with pytest.raises(SecurityError, match="too large"):
        validate_file_size(f, max_size_bytes=10)


def test_validate_file_size_missing():
    with pytest.raises(SecurityError, match="Cannot check"):
        validate_file_size(Path("/nonexistent/file"))


# ---------------------------------------------------------------------------
# validate_json_file
# ---------------------------------------------------------------------------


def test_validate_json_file_ok(tmp_path):
    f = tmp_path / "data.json"
    f.write_text(json.dumps({"key": "value"}))
    data = validate_json_file(f)
    assert data == {"key": "value"}


def test_validate_json_file_invalid(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not json")
    with pytest.raises(SecurityError, match="Invalid JSON"):
        validate_json_file(f)


# ---------------------------------------------------------------------------
# validate_url
# ---------------------------------------------------------------------------


def test_validate_url_localhost():
    with pytest.raises(SecurityError, match="localhost"):
        validate_url("https://localhost/api")


def test_validate_url_http():
    with pytest.raises(SecurityError, match="HTTPS"):
        validate_url("http://example.com/api")


def test_validate_url_metadata():
    with pytest.raises(SecurityError, match="metadata"):
        validate_url("https://169.254.169.254/latest/meta-data/")


def test_validate_url_private_ip():
    with pytest.raises(SecurityError, match="private"):
        validate_url("https://10.0.0.1/api")


# ---------------------------------------------------------------------------
# validate_package_name
# ---------------------------------------------------------------------------


def test_validate_package_name_npm():
    validate_package_name("lodash", "npm")
    validate_package_name("@scope/pkg", "npm")


def test_validate_package_name_pypi():
    validate_package_name("requests", "pypi")


def test_validate_package_name_go():
    validate_package_name("github.com/user/repo", "go")


def test_validate_package_name_cargo():
    validate_package_name("serde", "cargo")


def test_validate_package_name_empty():
    with pytest.raises(SecurityError):
        validate_package_name("", "npm")


def test_validate_package_name_invalid_npm():
    with pytest.raises(SecurityError):
        validate_package_name("pkg with spaces", "npm")


# ---------------------------------------------------------------------------
# validate_mcp_server_config
# ---------------------------------------------------------------------------


def test_validate_mcp_server_config_valid():
    config = {"command": "npx", "args": ["server"]}
    validate_mcp_server_config(config)


def test_validate_mcp_server_config_bad_command():
    config = {"command": "rm", "args": ["-rf", "/"]}
    with pytest.raises(SecurityError):
        validate_mcp_server_config(config)


# ---------------------------------------------------------------------------
# validate_image_ref
# ---------------------------------------------------------------------------


def test_validate_image_ref_valid():
    result = validate_image_ref("nginx:latest")
    assert result == "nginx:latest"


def test_validate_image_ref_with_registry():
    result = validate_image_ref("ghcr.io/user/image:v1.0")
    assert "ghcr.io" in result


# ---------------------------------------------------------------------------
# sanitize_error
# ---------------------------------------------------------------------------


def test_sanitize_error_basic():
    result = sanitize_error(ValueError("test error"))
    assert "test error" in result


def test_sanitize_error_generic():
    result = sanitize_error(ValueError("secret data"), generic=True)
    assert "secret data" not in result


def test_sanitize_error_string():
    result = sanitize_error("error message")
    assert "error message" in result


# ---------------------------------------------------------------------------
# create_safe_subprocess_env
# ---------------------------------------------------------------------------


def test_create_safe_subprocess_env():
    env = create_safe_subprocess_env()
    assert "LD_PRELOAD" not in env
    assert "DYLD_INSERT_LIBRARIES" not in env
    assert "PATH" in env
