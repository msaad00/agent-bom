"""Credential length must not bypass explicit bearer or product-key evidence."""

from pathlib import Path

import pytest

from agent_bom.runtime.patterns import CREDENTIAL_PATTERNS
from agent_bom.secret_scanner import scan_secrets
from agent_bom.security import sanitize_error, sanitize_text

PRODUCT_KEY = "abom_" + "aB9_" * 10 + "x-Y"
BEARER = "b7.c+~-_=="


@pytest.mark.parametrize("sanitize", [sanitize_error, sanitize_text])
@pytest.mark.parametrize("text,secret", [(f"Authorization: Bearer {BEARER}", BEARER), (f"received {PRODUCT_KEY}", PRODUCT_KEY)])
def test_error_and_log_paths_redact_recognizable_credentials(sanitize, text: str, secret: str) -> None:
    assert secret not in sanitize(text)


@pytest.mark.parametrize("text", ["Authorization: Bearer a", '"Authorization": "Bearer b7"', "token=Bearer c-3"])
def test_runtime_detects_short_bearer_header(text: str) -> None:
    pattern = dict(CREDENTIAL_PATTERNS)["Generic Bearer Token"]
    assert pattern.search(text)


@pytest.mark.parametrize("text", ["Authorization: Bearer", "Authorization: Bearer ${TOKEN}", "bearer token format", "abom_current_tenant"])
def test_runtime_does_not_invent_literal_credentials(text: str) -> None:
    assert not any(pattern.search(text) for _, pattern in CREDENTIAL_PATTERNS)


@pytest.mark.parametrize(
    "literal,expected", [(f"Authorization: Bearer {BEARER}", "Generic Bearer Token"), (PRODUCT_KEY, "Agent-Bom API Key")]
)
def test_file_scanner_reports_and_redacts_credential(tmp_path: Path, literal: str, expected: str) -> None:
    (tmp_path / "settings.py").write_text(f'VALUE = "{literal}"\n', encoding="utf-8")
    result = scan_secrets(tmp_path)
    assert any(finding.secret_type == expected for finding in result.findings)
    assert all(literal not in finding.matched_preview for finding in result.findings)


def test_product_key_pattern_preserves_noncredential_identifiers() -> None:
    text = "abom_current_tenant abom_policy_audit_key request_id=" + "a" * 64
    assert sanitize_text(text) == text
    assert sanitize_error(text) == text
