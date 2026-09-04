"""Machine-readable MCP protocol compatibility stays conservative and current."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from mcp.client.session import SUPPORTED_PROTOCOL_VERSIONS
from mcp.types import LATEST_PROTOCOL_VERSION

MANIFEST_PATH = Path(__file__).parents[1] / "src" / "agent_bom" / "data" / "mcp_protocol_compatibility.json"
KNOWN_STATES = {"supported", "unsupported", "unavailable", "not_applicable"}


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_protocol_manifest_records_current_and_readiness_eras() -> None:
    manifest = _manifest()

    assert manifest["schema_version"] == "agent-bom.mcp-protocol-compatibility.v1"
    eras = {entry["protocol_version"]: entry for entry in manifest["protocol_eras"]}
    assert set(eras) == {"2025-06-18", "2025-11-25", "2026-07-28"}
    assert eras["2025-06-18"]["state"] == "supported"
    assert eras["2025-11-25"]["state"] == "supported"
    assert eras["2026-07-28"]["state"] == "unsupported"
    assert eras["2026-07-28"]["assessment_status"] == "unavailable"
    assert eras["2026-07-28"]["verified_features"] == []
    assert eras["2026-07-28"]["reason_codes"] == [
        "not_in_locked_sdk_protocol_set",
        "compatibility_not_verified",
    ]


def test_supported_protocol_claims_are_bounded_by_the_sdk_contract() -> None:
    manifest = _manifest()
    claimed = {entry["protocol_version"] for entry in manifest["protocol_eras"] if entry["state"] == "supported"}

    assert claimed <= set(SUPPORTED_PROTOCOL_VERSIONS)
    assert manifest["sdk_policy"]["verified_latest_protocol"] == LATEST_PROTOCOL_VERSION == "2025-11-25"
    assert "2026-07-28" not in SUPPORTED_PROTOCOL_VERSIONS


def test_sdk_policy_matches_project_constraint_and_lock() -> None:
    manifest = _manifest()
    repo_root = Path(__file__).parents[1]
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    lock = tomllib.loads((repo_root / "uv.lock").read_text(encoding="utf-8"))
    dependency = next(item for item in project["dependencies"] if item.startswith("mcp>="))
    locked = next(item["version"] for item in lock["package"] if item["name"] == "mcp")

    assert manifest["sdk_policy"]["dependency"] == dependency
    assert manifest["sdk_policy"]["locked_version"] == locked


def test_feature_matrix_names_support_and_unavailable_states_explicitly() -> None:
    manifest = _manifest()
    features = manifest["features"]

    assert features["transports"] == {
        "stdio": "supported",
        "sse": "supported",
        "streamable-http": "supported",
    }
    assert features["capability_discovery"] == {
        "tools/list": "supported",
        "resources/list": "supported",
        "prompts/list": "supported",
    }
    assert features["auth"]["remote_static_bearer_server"] == "supported"
    assert features["auth"]["oauth_authorization_server"] == "supported"
    assert features["auth"]["authenticated_remote_introspection"] == "unsupported"
    assert features["auth"]["stdio_transport_auth"] == "not_applicable"

    states = {state for group in features.values() for state in group.values()}
    assert states <= KNOWN_STATES


def test_every_supported_claim_has_repo_evidence_and_every_gap_has_a_reason() -> None:
    manifest = _manifest()
    repo_root = Path(__file__).parents[1]

    for entry in manifest["evidence"]:
        evidence_path = repo_root / entry["path"]
        assert evidence_path.is_file(), entry

    for group in manifest["features"].values():
        for name, state in group.items():
            key = f"{name}:{state}"
            if state in {"unsupported", "unavailable"}:
                assert key in manifest["limitations"]
