"""Scan-export hot paths: equivalence with the prior implementations, redaction
coverage, and a cold-start import surface that does not pull in the SDK.

The optimized traversal must preserve the uncached walk with today's complete
leaf policy, including cloud coordinates and discovery provenance. The other
equivalence tests retain the previous implementation over a seeded corpus of
ANSI escapes, C0/C1 controls,
DEL, unicode separators, credential shapes, URLs, emails and key=value text.
"""

from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import agent_bom.security as security
from agent_bom.constants import is_credential_key
from agent_bom.redaction.payload import sanitize_string

_SRC_ROOT = str(Path(__file__).resolve().parents[1] / "src")

# ── Reference (previous) implementations ────────────────────────────────────


def _ref_sanitize_log_label(value: object, max_len: int = 500) -> str:
    text = security.ANSI_ESCAPE_RE.sub("", str(value))
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    return re.sub(r" {2,}", " ", text).strip()[:max_len]


def _ref_env_key_is_credential(key: str) -> bool:
    low = key.lower()
    return is_credential_key(key) or any(re.search(pattern, low) for pattern in security.SENSITIVE_PATTERNS)


def _ref_key_looks_sensitive(key: object) -> bool:
    return any(re.search(pattern, str(key).lower()) for pattern in security.SENSITIVE_PATTERNS)


def _ref_sanitize_env_vars(env: dict[str, Any]) -> dict[str, str]:
    sanitized = {}
    for key, value in env.items():
        if _ref_env_key_is_credential(key):
            sanitized[key] = "***REDACTED***"
        else:
            str_value = str(value)
            if security._contains_value_credential(str_value):
                sanitized[key] = "***REDACTED***"
            elif security._is_obfuscated_credential(str_value):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = str_value
    return sanitized


def _ref_looks_sensitive_value(value: str) -> bool:
    return _ref_sanitize_env_vars({"ARG": value}).get("ARG") == "***REDACTED***"


def _ref_sanitize_text(value: object, max_len: int = 1000) -> str:
    text = _ref_sanitize_log_label(value, max_len=max_len)
    text = re.sub(r"https?://[^\s\"'<>]+", lambda match: str(security.sanitize_url(match.group(0)) or ""), text)
    for pattern in security._VALUE_CREDENTIAL_PATTERNS:
        text = pattern.sub("<redacted>", text)
    if "://" in text:
        text = security._CONNECTION_CREDENTIAL_RE.sub("://<redacted>@", text)
    text = security._TEXT_KEY_VALUE_RE.sub(security._redact_keyed_value, text)
    text = security.mask_email(text)
    return text[:max_len]


def _ref_sanitize_sensitive_payload(value: object, *, key: object | None = None, max_str_len: int = 1000, depth: int = 0) -> object:
    if depth >= 24:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return sanitize_string(value, key, max_str_len)
    if isinstance(value, dict):
        sanitized: dict[str, object] = {}
        for raw_key, raw_value in value.items():
            clean_key = security.sanitize_text(raw_key, max_len=200)
            sanitized[clean_key] = _ref_sanitize_sensitive_payload(raw_value, key=clean_key, max_str_len=max_str_len, depth=depth + 1)
        return sanitized
    if isinstance(value, list | tuple | set):
        return [_ref_sanitize_sensitive_payload(item, key=key, max_str_len=max_str_len, depth=depth + 1) for item in list(value)]
    return security.sanitize_text(value, max_len=max_str_len)


# ── Seeded corpus ───────────────────────────────────────────────────────────

_ATOMS = [
    "a",
    "Z",
    "0",
    " ",
    "  ",
    "\t",
    "\n",
    "\r",
    "\r\n",
    "\x00",
    "\x01",
    "\x07",
    "\x0b",
    "\x0c",
    "\x1b",
    "\x1f",
    "\x7f",
    "\x80",
    "\x9b",
    "\u00a0",
    "\u2028",
    "\u2029",
    "\u200b",
    "\ufeff",
    "é",
    "中文",
    "🙂",
    "e\u0301",
    "\x1b[31m",
    "\x1b[0m",
    "\x1b[1;32;40m",
    "\x1b]0;title\x07",
    "=",
    ":",
    ": ",
    '"',
    "'",
    "/",
    "@",
    "->",
    "pkg:npm/lodash@4.17.20",
    "https://user:pa55word@example.com/path?token=abc#frag",
    "http://example.com/x",
    "postgres://svc:hunter2hunter2@db.internal:5432/app",
    "alice@example.com",
    "@scope/pkg",
    "password=hunter2hunter2",
    "API_KEY: s3cr3tvalue99",
    '"token": "abcdefghijk"',
    "OPENAI_API_KEY",
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz012345",
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "xoxb-" + "1234567890-abcdef",
    "eyJ" + "a" * 24 + ".eyJ" + "b" * 24,
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "q7V9mK2xR8pL4nT6wY1cF3hJ5sD0aB2eG8uN9zQ6XkI=",
    "/Users/alice/secrets/key.env",
    "C:\\Users\\bob\\file.txt",
    "~/project",
    "Hardcoded credential: Stripe Key",
    "CVE-2024-12345",
    "arn:aws:iam::123456789012:role/Admin",
]


def _corpus(seed: int, count: int) -> list[str]:
    rng = random.Random(seed)
    strings = list(_ATOMS)
    for _ in range(count):
        parts = rng.choices(_ATOMS, k=rng.randint(1, 8))
        if rng.random() < 0.3:
            parts.append("".join(chr(rng.randint(0, 0x2FFF)) for _ in range(rng.randint(1, 12))))
        strings.append("".join(parts))
    strings.append("x" * 1200)
    strings.append(" " * 50 + "padded" + " " * 50)
    return strings


# ── Equivalence ─────────────────────────────────────────────────────────────


def test_sanitize_log_label_matches_previous_implementation() -> None:
    for text in _corpus(seed=1, count=6000):
        for max_len in (500, 7, 1000):
            assert security.sanitize_log_label(text, max_len=max_len) == _ref_sanitize_log_label(text, max_len=max_len), repr(text)
    for value in (None, 12, 3.5, True, b"bytes\n", Path("/tmp/a\tb")):
        assert security.sanitize_log_label(value) == _ref_sanitize_log_label(value)


def test_sanitize_log_label_every_code_point_below_0x3000() -> None:
    for code_point in range(0x3000):
        if 0xD800 <= code_point <= 0xDFFF:
            continue
        text = f"a{chr(code_point)}b  {chr(code_point)}"
        assert security.sanitize_log_label(text) == _ref_sanitize_log_label(text), hex(code_point)


def test_whitespace_regexes_match_str_isspace_for_every_code_point() -> None:
    for code_point in range(sys.maxunicode + 1):
        character = chr(code_point)
        assert bool(security._WHITESPACE_RE.search(character)) == character.isspace(), hex(code_point)
        expected = character.isspace() or code_point < 32
        assert bool(security._WHITESPACE_OR_C0_RE.search(character)) == expected, hex(code_point)


def test_sanitize_text_matches_previous_implementation() -> None:
    for text in _corpus(seed=2, count=4000):
        assert security.sanitize_text(text) == _ref_sanitize_text(text), repr(text)
        assert security.sanitize_text(text, max_len=40) == _ref_sanitize_text(text, max_len=40), repr(text)


def test_credential_predicates_match_previous_implementation() -> None:
    keys = _corpus(seed=3, count=1500) + [
        "ARG",
        "api-key",
        "apikey",
        "Authorization",
        "jwt_secret",
        "BEARER",
        "credential_env_vars",
        "name",
        "AUTH_MODE",
        "KEYBOARD_LAYOUT",
    ]
    for key in keys:
        assert security.env_key_is_credential(key) == _ref_env_key_is_credential(key), repr(key)
        assert security._key_looks_sensitive(key) == _ref_key_looks_sensitive(key), repr(key)
    # _looks_sensitive_value skips the name check because this placeholder is not credential-named.
    assert not _ref_env_key_is_credential("ARG")
    for value in _corpus(seed=4, count=3000):
        assert security._looks_sensitive_value(value) == _ref_looks_sensitive_value(value), repr(value)


@pytest.mark.parametrize("url", ["https://host:abc/x", "http://127.0.0.1:99999/", "https://user:pa55@host:port/path?q=1"])
def test_malformed_url_port_in_free_text_does_not_abort_redaction(url: str) -> None:
    from agent_bom.output.json_fmt import redact_json_payload

    assert security.sanitize_url(url) == "<redacted-url>"
    text = f"Service mirror at {url} returned 500"
    assert "pa55" not in security.sanitize_text(text)
    redacted = redact_json_payload({"findings": [{"description": text, "remediation": url}]})
    assert "pa55" not in json.dumps(redacted)
    assert redacted["findings"][0]["description"].startswith("Service mirror at ")


_PAYLOAD_KEYS = [
    "name",
    "version",
    "description",
    "title",
    "id",
    "canonical_id",
    "purl",
    "node_id",
    "source",
    "target",
    "token",
    "password",
    "api_key",
    "Authorization",
    "url",
    "endpoint",
    "path",
    "config_path",
    "email",
    "user_email",
    "credentials_exposed",
    "region",
    "account_id",
    "auth_mode",
    "evidence",
    "details",
    "env",
]


def _random_payload(rng: random.Random, strings: list[str], depth: int) -> object:
    roll = rng.random()
    if depth > 28 or roll < 0.45:
        pick = rng.random()
        if pick < 0.7:
            return rng.choice(strings)
        return rng.choice([None, True, False, 0, 7, 3.25, Path("/home/u/.ssh/id_rsa")])
    if roll < 0.75:
        return {rng.choice(_PAYLOAD_KEYS + strings[:40]): _random_payload(rng, strings, depth + 1) for _ in range(rng.randint(0, 5))}
    container = [_random_payload(rng, strings, depth + 1) for _ in range(rng.randint(0, 4))]
    return tuple(container) if rng.random() < 0.2 else container


def test_sanitize_sensitive_payload_matches_previous_walk() -> None:
    rng = random.Random(5)
    strings = _corpus(seed=6, count=400)
    for _ in range(300):
        payload = _random_payload(rng, strings, 0)
        assert security.sanitize_sensitive_payload(payload) == _ref_sanitize_sensitive_payload(payload)
    deep: object = "leaf"
    for index in range(40):
        deep = {"token" if index % 3 == 0 else "child": [deep, index]}
    assert security.sanitize_sensitive_payload(deep) == _ref_sanitize_sensitive_payload(deep)


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        (
            "resource_id",
            "/subscriptions/example/providers/Microsoft.KeyVault/vaults/shared",
            "/subscriptions/example/providers/Microsoft.KeyVault/vaults/shared",
        ),
        ("node_id", "arn:aws:iam::123456789012:role/Admin", "arn:aws:iam::123456789012:role/Admin"),
        (
            "resource_ids",
            "projects/example/locations/us-central1/services/shared",
            "projects/example/locations/us-central1/services/shared",
        ),
        ("discovery_sources", "project-config:/home/example/.mcp.json", "project-config:<path:.mcp.json>"),
        ("id", "C:\\Users\\example\\file.txt", "<path:file.txt>"),
        ("password", "arn:aws:iam::123456789012:role/Admin", "***REDACTED***"),
        ("id", "arn:aws:lambda:us-east-1:123456789012:function:ghp_" + "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5", "***REDACTED***"),
    ],
)
def test_cached_and_uncached_walks_apply_current_identity_policy(key, value, expected):
    payload = {key: [value, value, {key: (value,)}]}
    result = {key: [expected, expected, {key: [expected]}]}
    assert sanitize_string(value, key, 1000) == expected
    assert _ref_sanitize_sensitive_payload(payload) == result
    assert security.sanitize_sensitive_payload(payload) == result


# ── Redaction coverage on report-shaped payloads ─────────────────────────────


def test_redact_json_payload_redacts_secrets_in_nested_finding_fields() -> None:
    from agent_bom.output.json_fmt import redact_json_payload

    github_token = "ghp_" + "Zy9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa"
    stripe_key = "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz012345"
    aws_key_id = "AKIA" + "QWERTYUIOPASDFGH"
    opaque = "q7V9mK2xR8pL4nT6wY1cF3hJ5sD0aB2eG8uN9zQ6XkI="
    report = {
        "document_type": "AI-BOM",
        "findings": [
            {
                "id": "finding-1",
                "title": f"Leaked token {github_token}",
                "evidence": {
                    "env": {"OPENAI_API_KEY": "sk-" + "abcdefghijklmnopqrstuvwx"},
                    "snippet": f"password = {opaque}",
                    "nested": [{"api_key": "plain-looking"}, {"note": f"key {stripe_key} leaked"}],
                    "remote": "https://deploy:hunter2hunter2@git.example.com/org/repo.git?token=abc",
                    "contact": "alice@example.com",
                    "file_path": "/Users/alice/prod/secrets.env",
                },
                "asset": {"name": "api-server", "identifier": f"pkg:npm/{opaque}@1.0"},
            }
        ],
        "blast_radius": [{"vulnerability_id": "CVE-2024-1", "affected_servers": [{"env": {"AWS_ACCESS_KEY_ID": aws_key_id}}]}],
        "agents": [{"name": "agent", "mcp_servers": [{"args": [f"--token={github_token}"], "url": "https://x.example.com/?key=1"}]}],
    }

    encoded = json.dumps(redact_json_payload(report))

    for secret in (github_token, stripe_key, aws_key_id, opaque, "hunter2hunter2", "plain-looking", "alice@example.com", "/Users/alice"):
        assert secret not in encoded, secret
    redacted = redact_json_payload(report)
    finding = redacted["findings"][0]
    assert finding["id"] == "finding-1"
    assert finding["asset"]["name"] == "api-server"
    assert finding["evidence"]["nested"][0]["api_key"] == "***REDACTED***"
    assert finding["evidence"]["contact"] == "a***@e***.com"
    assert finding["evidence"]["file_path"].startswith("<path:")


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"a": 1},
        {"a": {}, "b": [], "c": None, "d": 'é中🙂\n"', "e": [1, {"x": [True, 2.5]}]},
        {1: "int-key", "nested": {"deep": {"deeper": ["a", {"k": {}}]}}, "empty_list": [], "last": {}},
    ],
)
def test_sectioned_json_writer_is_byte_identical_to_json_dump(data: dict) -> None:
    import io

    from agent_bom.output.json_writer import write_json_document

    expected, actual = io.StringIO(), io.StringIO()
    json.dump(data, expected, indent=2)
    expected.write("\n")
    write_json_document(data, actual)
    assert actual.getvalue() == expected.getvalue()


def test_export_json_writes_indented_redacted_payload(tmp_path: Path) -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import export_json, to_redacted_json

    report = AIBOMReport(agents=[], blast_radii=[], scan_id="perf-export")
    report_json = {"document_type": "AI-BOM", "scan_id": "perf-export", "nested": {"token": "abc123secret", "items": [1, "two"]}}
    out = tmp_path / "report.json"

    export_json(report, str(out), report_json=report_json)

    expected = json.dumps(to_redacted_json(report, report_json=report_json), indent=2) + "\n"
    assert out.read_text(encoding="utf-8") == expected
    assert "abc123secret" not in out.read_text(encoding="utf-8")


# ── Cold start / import surface ─────────────────────────────────────────────


def _run_python(code: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False, timeout=120)


def test_package_root_import_is_lazy() -> None:
    proc = _run_python(
        "import sys, agent_bom\n"
        "heavy = sorted(m for m in ('agent_bom.sdk', 'agent_bom.client', 'mcp', 'mcp.server.fastmcp') if m in sys.modules)\n"
        "print(','.join(heavy))\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ""


def test_cli_help_does_not_import_sdk_or_demo_presentation() -> None:
    proc = _run_python(
        "import sys\n"
        "from click.testing import CliRunner\n"
        "from agent_bom.cli import main\n"
        "result = CliRunner().invoke(main, ['--help'])\n"
        "assert result.exit_code == 0, result.output\n"
        "heavy = ('agent_bom.sdk', 'mcp.server.fastmcp', 'agent_bom.demo_estate.presentation')\n"
        "print(','.join(sorted(m for m in heavy if m in sys.modules)))\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ""


def test_package_root_public_api_still_resolves() -> None:
    import agent_bom
    import agent_bom.sdk as sdk

    for name in agent_bom.__all__:
        assert getattr(agent_bom, name) is not None, name
    assert agent_bom.scan is sdk.scan
    assert agent_bom.check is sdk.check
    assert agent_bom.async_check is sdk.async_check
    assert agent_bom.diff is sdk.diff
    assert agent_bom.AgentBomSDKError is sdk.AgentBomSDKError
    assert set(agent_bom.__all__) <= set(dir(agent_bom))
    with pytest.raises(AttributeError):
        agent_bom.does_not_exist  # noqa: B018

    proc = _run_python(
        "from agent_bom import scan, check, async_check, diff, AgentBomSDKError, DiffResult, InventoryResult, "
        "PackageCheckResult, AgentBomApiError, AgentBomClient, __version__\n"
        "from agent_bom import scan_cache\n"
        "import agent_bom\n"
        "print(scan.__module__, scan_cache.__name__, bool(agent_bom.__version__))\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["agent_bom.sdk", "agent_bom.scan_cache", "True"]


def test_python_dash_m_agent_bom_runs_cli() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-m", "agent_bom", "--version"], capture_output=True, text=True, env=env, check=False, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    from agent_bom import __version__

    assert __version__ in proc.stdout
