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


def test_reference_lab_proves_exact_end_to_end_chain() -> None:
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
    assert payload["correlation"]["receipt_verification"] == {
        "status": "verified",
        "verified": 6,
        "legacy_hash_bound": 0,
        "invalid": 0,
        "verification_key_unavailable": 0,
        "total": 6,
    }

    proof = payload["proof_path"]
    assert proof["reachability"] == "confirmed"
    assert len(proof["hops"]) == 8
    assert len(proof["hop_evidence"]) == 7
    assert all(receipt["complete"] for receipt in proof["hop_evidence"])
    assert all(receipt["source_snapshot_ids"] for receipt in proof["hop_evidence"])
    assert {receipt["evidence_tier"] for receipt in proof["hop_evidence"]} >= {
        "static_evidence",
        "modeled_infrastructure",
        "runtime_observed",
    }
    assert any(receipt["runtime_observed_state"] == "observed" for receipt in proof["hop_evidence"])
    assert payload["runtime_control"]["strict_block"] == "verified"
    assert payload["runtime_control"]["verification"] == "live_jsonrpc_gateway_smoke"
    assert payload["runtime_control"]["allow_result"] == "upstream_called"
    assert payload["runtime_control"]["blocked_error_code"] == -32001
    assert payload["runtime_control"]["policy_source"] == "graph_reachability"
    assert payload["runtime_control"]["tool_id"] == "mcp-tool:reference-lab:render-untrusted-image"
    assert proof["analysis"]["status"] == "complete"
    assert proof["finding_ids"] == ["reference-finding-cve-2023-4863"]

    decision = payload["remediation_decision"]
    assert decision["schema_version"] == "agent-bom.graph-correlation-remediation/v1"
    assert decision["correlation_id"] == payload["correlation"]["correlation_id"]
    assert decision["snapshot_id"] == payload["correlation"]["output_scan_id"]
    assert decision["correlation_manifest_sha256"] == payload["correlation"]["manifest_sha256"]
    assert decision["finding"] == {
        "finding_id": "reference-finding-cve-2023-4863",
        "advisory_id": "CVE-2023-4863",
        "is_kev": True,
        "severity": "high",
    }
    assert decision["package"] == {
        "node_id": "package:sbom:pillow",
        "name": "pillow",
        "ecosystem": "pypi",
        "purl": "pkg:pypi/pillow@9.0.0",
        "current_version": "9.0.0",
    }
    assert decision["container"]["node_id"] == "container:iac:reference-api"
    assert decision["container"]["image_digest"] == payload["container_digest"]
    assert decision["path"]["hops"] == proof["hops"]
    assert decision["path"]["relationships"] == proof["edges"]
    assert decision["path"]["identity"] == (
        f"{proof['source']}::{proof['target']}::{'->'.join(proof['hops'])}"
    )
    assert decision["ownership"] == {"owner": None, "status": "unassigned"}
    assert decision["sla"]["due_at"] == "2023-10-04T00:00:00+00:00"
    assert decision["sla"]["status"] == "overdue"
    assert decision["recommendation"]["action"] == "upgrade"
    assert decision["recommendation"]["fixed_version"] == "10.0.1"
    assert decision["recommendation"]["command"] == "pip install 'pillow>=10.0.1'"
    assert decision["recommendation"]["applied"] is False
    assert decision["verification"]["command"] == "agent-bom scan . --offline"
    assert decision["verification"]["status"] == "not_run"
    assert decision["reverification"]["rescan_status"] == "not_run"
    assert decision["reverification"]["recorrelation_status"] == "not_run"
    assert decision["reverification"]["predecessor_snapshot_id"] == decision["snapshot_id"]
    assert decision["evidence_scope"] == {
        "customer_evidence": False,
        "infrastructure": "modeled_local",
        "live_cloud": False,
        "name": "reference_evidence_lab",
    }

    capture = payload["capture_fixture"]
    assert capture["graph"]["scan_id"] == payload["correlation"]["output_scan_id"]
    assert capture["graph"]["attack_paths"] == [proof]
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
