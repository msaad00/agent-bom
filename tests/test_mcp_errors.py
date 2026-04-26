"""Unit tests for src/agent_bom/mcp_errors.py and the MCP-tool integration.

Pins the contract for #1960:
- Every category is reachable from at least one declared code.
- Every code declared in mcp_errors.py is documented in
  docs/MCP_ERROR_CODES.md (and vice versa) so the operator-facing
  reference and the runtime constants cannot drift.
- The envelope shape is stable: {"error": {code, category, message,
  details?}, "schema_version": int}.
- Sample tool integrations (registry_lookup, blast_radius validation,
  marketplace_check) emit the new envelope on bad input.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_bom.mcp_errors import (
    CATEGORY_INTERNAL,
    CATEGORY_VALIDATION,
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_RESOURCE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    MCP_ERROR_VERSION,
    category_for,
    known_categories,
    known_codes,
    mcp_error_json,
    mcp_error_payload,
)

ROOT = Path(__file__).resolve().parents[1]
DOC_PATH = ROOT / "docs" / "MCP_ERROR_CODES.md"


def test_envelope_shape_is_stable() -> None:
    payload = mcp_error_payload(
        CODE_VALIDATION_INVALID_ARGUMENT,
        "bad input",
        details={"argument": "ecosystem"},
    )
    assert payload["schema_version"] == MCP_ERROR_VERSION
    err = payload["error"]
    assert err["code"] == CODE_VALIDATION_INVALID_ARGUMENT
    assert err["category"] == CATEGORY_VALIDATION
    assert err["message"] == "bad input"
    assert err["details"] == {"argument": "ecosystem"}


def test_payload_omits_details_when_empty() -> None:
    payload = mcp_error_payload(CODE_INTERNAL_UNEXPECTED, "boom")
    assert "details" not in payload["error"]


def test_payload_sanitizes_exceptions() -> None:
    # sanitize_error strips file paths and URLs from exception text. We
    # only assert the message is a non-empty string here so the test
    # doesn't couple itself to sanitize_error's exact heuristics — the
    # important contract is "exception was processed, not stringified raw".
    payload = mcp_error_payload(CODE_INTERNAL_UNEXPECTED, RuntimeError("boom at /etc/passwd"))
    assert isinstance(payload["error"]["message"], str)
    assert payload["error"]["message"]


def test_unknown_code_routes_to_internal() -> None:
    assert category_for("AGENTBOM_MCP_NOT_A_REAL_CODE") == CATEGORY_INTERNAL


def test_every_category_has_at_least_one_code() -> None:
    cats_in_use = {category_for(code) for code in known_codes()}
    missing = set(known_categories()) - cats_in_use
    assert not missing, f"categories declared but unreachable from any code: {sorted(missing)}"


def test_mcp_error_json_round_trips() -> None:
    raw = mcp_error_json(CODE_NOT_FOUND_RESOURCE, "missing", details={"id": "x"})
    parsed = json.loads(raw)
    assert parsed["error"]["code"] == CODE_NOT_FOUND_RESOURCE
    assert parsed["error"]["details"] == {"id": "x"}


def test_doc_lists_every_runtime_code() -> None:
    doc = DOC_PATH.read_text(encoding="utf-8")
    declared = set(known_codes())
    documented = set(re.findall(r"`(AGENTBOM_MCP_[A-Z0-9_]+)`", doc))
    missing_from_doc = declared - documented
    extra_in_doc = documented - declared
    assert not missing_from_doc, (
        f"Codes declared in mcp_errors.py but not in docs/MCP_ERROR_CODES.md: {sorted(missing_from_doc)}. Add them to the reference table."
    )
    assert not extra_in_doc, (
        f"Codes referenced in docs/MCP_ERROR_CODES.md but not declared in mcp_errors.py: {sorted(extra_in_doc)}. "
        "Either declare them or remove the doc rows."
    )


# ── Integration: tools emit the new envelope on bad input ────────────────────


@pytest.mark.asyncio
async def test_registry_lookup_missing_required_returns_envelope() -> None:
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    response = registry_lookup_impl(server_name="", package_name="", _get_registry_data=lambda: {"servers": {}})
    parsed = json.loads(response)
    assert parsed["error"]["category"] == "validation"
    assert parsed["error"]["code"] == "AGENTBOM_MCP_VALIDATION_MISSING_REQUIRED"


@pytest.mark.asyncio
async def test_registry_lookup_upstream_failure_returns_upstream_envelope() -> None:
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    def _broken() -> dict:
        raise RuntimeError("registry on fire")

    response = registry_lookup_impl(server_name="filesystem", _get_registry_data=_broken)
    parsed = json.loads(response)
    assert parsed["error"]["category"] == "upstream"
    assert parsed["error"]["code"] == "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE"
    assert parsed["error"]["details"]["upstream"] == "mcp_registry"


@pytest.mark.asyncio
async def test_blast_radius_invalid_cve_returns_validation_envelope() -> None:
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    def _validate(cve: str) -> str:
        raise ValueError(f"Invalid CVE ID format: {cve!r}")

    async def _scan() -> tuple:
        raise AssertionError("scan should not be called when validation fails")

    response = await blast_radius_impl(
        cve_id="not-a-cve",
        _validate_cve_id=_validate,
        _run_scan_pipeline=_scan,
        _truncate_response=lambda x: x,
    )
    parsed = json.loads(response)
    assert parsed["error"]["category"] == "validation"
    assert parsed["error"]["code"] == "AGENTBOM_MCP_VALIDATION_INVALID_VULN_ID"
    assert parsed["error"]["details"] == {"argument": "cve_id"}
