"""Credential strings are private; safe IaC source labels remain actionable."""

import json

import pytest

from agent_bom.finding import iac_finding_to_finding
from agent_bom.finding_scope import safe_finding_response_payload
from agent_bom.security import sanitize_sensitive_payload, sanitize_text


@pytest.mark.parametrize("credential", ["Bearer to1", "bEaReR abC-._~+/==", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"])
def test_credentials_are_redacted_in_text_and_arbitrary_payload_values(credential):
    assert credential not in sanitize_text(f"diagnostic {credential}")
    assert credential not in json.dumps(sanitize_sensitive_payload({"description": credential}))


def test_iac_safe_source_keeps_basename_and_line_without_local_directory():
    finding = iac_finding_to_finding({"rule_id": "TF-S3-001", "file_path": "/private/work/customer/main.tf", "line_number": 1})
    row = sanitize_sensitive_payload(finding.to_dict())
    safe = safe_finding_response_payload(row)
    assert safe["asset"]["name"] == "main.tf:1"
    assert safe_finding_response_payload(safe)["asset"]["name"] == "main.tf:1"
    assert "/private/work" not in json.dumps(safe)


@pytest.mark.parametrize("line", [True, False, -1, 0, 2**32, "1", None])
def test_iac_display_rejects_untrusted_line_numbers(line):
    row = {
        "asset": {"asset_type": "iac_resource", "name": "/private/customer/main.tf"},
        "evidence": {"file_path": "/private/customer/main.tf", "line_number": line},
    }
    safe = safe_finding_response_payload(row)
    assert safe["asset"]["name"] == "main.tf"
    assert safe_finding_response_payload(safe)["asset"]["name"] == "main.tf"
    assert "/private/customer" not in json.dumps(safe)


def test_ordinary_identifiers_are_not_short_jwts_or_bearer_tokens():
    for value in ["requests@2.32.4", "eyJexample", "foo.bar.baz", "bearer-token-type", "main.tf:1"]:
        assert sanitize_text(value) == value


@pytest.mark.parametrize("kind", ["uv", "pnpm"])
def test_lockfile_provenance_keeps_the_actual_source_label(kind, tmp_path):
    from agent_bom.parsers.node_parsers import parse_pnpm_lock
    from agent_bom.parsers.uv_lock import parse_uv_lock
    from agent_bom.security import sanitize_path_label

    if kind == "uv":
        filename = "uv.lock"
        (tmp_path / filename).write_text(
            'version = 1\n[[package]]\nname = "requests"\nversion = "2.32.4"\nsource = { registry = "https://pypi.org/simple" }\n'
        )
        packages = parse_uv_lock(tmp_path)
    else:
        filename = "pnpm-lock.yaml"
        (tmp_path / filename).write_text("lockfileVersion: '9.0'\npackages:\n  next@15.2.2: {}\n")
        packages = parse_pnpm_lock(tmp_path)
    assert packages
    assert {sanitize_path_label(e["source_file"]) for p in packages for e in p.version_evidence} == {f"<path:{filename}>"}
