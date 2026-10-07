from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "examples" / "reference-evidence-lab"
OUTPUT = LAB / "generated" / "correlation-proof.json"
OUTPUT_DIGEST = LAB / "generated" / "correlation-proof.sha256"


def test_reference_lab_generated_output_is_current() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_reference_evidence_lab.py"), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_reference_lab_generated_output_has_a_file_digest() -> None:
    expected = f"sha256:{hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}"

    assert OUTPUT_DIGEST.read_text(encoding="utf-8").strip() == expected


def test_reference_lab_vulnerable_input_is_not_an_installable_manifest() -> None:
    pinned_input = LAB / "pinned-package.txt"

    assert pinned_input.read_text(encoding="utf-8") == "Pillow==9.0.0\n"
    assert not (LAB / "requirements.txt").exists()


def test_reference_lab_preserves_source_receipts_and_evidence_boundaries() -> None:
    payload = json.loads(OUTPUT.read_text(encoding="utf-8"))

    assert payload["label"] == "Reference evidence lab — modeled local infrastructure"
    assert payload["scanner_evidence"]["evidence_input"] == "examples/reference-evidence-lab/pinned-package.txt"
    assert payload["scanner_evidence"]["scanner_manifest"] == "isolated temporary requirements.txt"
    assert payload["scanner_evidence"]["package"] == "pkg:pypi/pillow@9.0.0"
    assert payload["scanner_evidence"]["advisory"] == "CVE-2023-4863"
    assert payload["container_digest"].startswith("sha256:")
    assert len(payload["container_digest"]) == 71
    assert len(payload["correlation"]["input_manifest"]) == 6
    assert all(
        receipt["signature"]["schema_version"] == "agent-bom.correlation-receipt-signature/v1"
        and receipt["signature"]["algorithm"] == "hmac-sha256"
        and receipt["signature"]["key_id"] == "reference-lab-v1"
        for receipt in payload["correlation"]["input_manifest"]
    )

    path = payload["proof_path"]
    assert path["edges"] == ["uses", "authenticates_as", "has_permission"]
    assert path["vuln_ids"] == []
    assert path["tool_exposure"] == []
    assert all(hop["runtime_observed_state"] == "not_observed" for hop in path["hop_evidence"])
    assert payload["evidence_matrix"]["exploitability"]["status"] == "not_established"
    assert payload["evidence_matrix"]["granted_access"]["status"] == "modeled"
    assert payload["runtime_control"]["strict_block"] == "verified"
    assert payload["runtime_control"]["verification"] == "live_jsonrpc_gateway_smoke"
    assert payload["runtime_control"]["allow_result"] == "upstream_called"
    assert payload["runtime_control"]["blocked_error_code"] == -32001
    assert payload["runtime_control"]["policy_source"] == "file"
    assert payload["runtime_control"]["tool_id"] == "mcp-tool:reference-lab:render-untrusted-image"

    capture = payload["capture_fixture"]
    assert capture["graph"]["scan_id"] == payload["correlation"]["output_scan_id"]
    assert capture["graph"]["attack_paths"] == [path]
    assert len(capture["fix_first"]["cards"]) == 1
    assert len(capture["snapshots"]) == 6
    assert all(snapshot["snapshot_kind"] == "scan" for snapshot in capture["snapshots"])


def test_reference_lab_receipts_bind_real_input_artifacts_and_parsers() -> None:
    payload = json.loads(OUTPUT.read_text(encoding="utf-8"))
    receipts = payload["source_artifacts"]

    assert set(receipts) == {"dependency", "sbom", "kubernetes", "mcp", "identity"}
    assert receipts["dependency"]["parser"] == "agent_bom.parsers.scan_project_directory"
    assert receipts["sbom"]["parser"] == "agent_bom.sbom.load_sbom"
    assert receipts["kubernetes"]["parser"] == "agent_bom.iac.scan_iac_with_context + yaml.safe_load_all"
    assert receipts["mcp"]["parser"] == "agent_bom.discovery.parse_mcp_config"
    assert receipts["identity"]["parser"] == "strict local identity model parser"
    for receipt in receipts.values():
        source = ROOT / receipt["path"]
        assert source.is_file()
        assert receipt["sha256"] == f"sha256:{hashlib.sha256(source.read_bytes()).hexdigest()}"


def test_reference_lab_never_uses_mutable_identity_for_cross_source_joins() -> None:
    payload = json.loads(OUTPUT.read_text(encoding="utf-8"))

    assert payload["join_receipts"]
    assert {receipt["basis"] for receipt in payload["join_receipts"]} <= {
        "exact_purl",
        "oci_digest",
        "kubernetes_uid",
        "provider_identity_id",
        "stable_runtime_id",
        "canonical_advisory_id",
    }
    serialized = json.dumps(payload["join_receipts"], sort_keys=True).lower()
    assert "latest" not in serialized
    assert "label" not in serialized


def test_reference_lab_does_not_claim_a_source_import_from_a_dependency_manifest() -> None:
    payload = json.loads(OUTPUT.read_text(encoding="utf-8"))
    dependency_edges = [edge for edge in payload["capture_fixture"]["graph"]["edges"] if edge["source"] == "source:pinned-package"]

    assert len(dependency_edges) == 1
    assert dependency_edges[0]["relationship"] == "depends_on"


def test_reference_lab_keeps_image_inventory_separate_from_deployment_occurrences() -> None:
    payload = json.loads(OUTPUT.read_text(encoding="utf-8"))
    containers = [node for node in payload["capture_fixture"]["graph"]["nodes"] if node["entity_type"] == "container"]
    assert len(containers) == 2
    assert all(receipt["basis"] != "oci_digest" for receipt in payload["join_receipts"])
    assert payload["artifact_bindings"][0]["basis"] == "modeled_pinned_image_composition"


def test_reference_lab_does_not_invent_exploitability_or_resource_activity() -> None:
    payload = json.loads(OUTPUT.read_text(encoding="utf-8"))
    graph = payload["capture_fixture"]["graph"]
    assert not any(edge["relationship"] == "exploitable_via" for edge in graph["edges"])
    assert not any(edge["relationship"] == "accessed" for edge in graph["edges"])
    assert not any(edge["relationship"] == "authenticates_as" and edge["evidence"].get("runtime_observed") for edge in graph["edges"])
    assert all(node["risk_score"] == 0 for node in graph["nodes"] if node["entity_type"] in {"tool", "data_store"})
    assert payload["runtime_control"]["policy_source"] == "file"
    assert payload["evidence_matrix"]["resource_activity"]["status"] == "not_observed"


def test_reference_lab_local_session_contains_real_before_after_scans(tmp_path):
    destination = tmp_path / "session"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_reference_evidence_lab.py"), "--output-dir", str(destination)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    session = json.loads((destination / "local-session.json").read_text())
    assert session["schema_version"] == "agent-bom.reference-lab-session/v1"
    assert [scan["phase"] for scan in session["scans"]] == ["before", "after"]
    assert session["scans"][0]["input_sha256"] != session["scans"][1]["input_sha256"]
    for scan in session["scans"]:
        assert scan["result"]["document_type"] == "AI-BOM"
        assert scan["result"]["agents"]
        assert scan["input_sha256"] == hashlib.sha256((destination / (scan["phase"] + "-input.txt")).read_bytes()).hexdigest()
    verification = session["remediation_verification"]
    assert "CVE-2023-4863" in verification["before"]
    assert "CVE-2023-4863" not in verification["after"]
    original = (destination / "local-session.json").read_bytes()
    repeat = subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_reference_evidence_lab.py"), "--output-dir", str(destination)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert repeat.returncode != 0
    assert (destination / "local-session.json").read_bytes() == original
