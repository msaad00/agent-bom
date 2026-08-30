from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "examples" / "reference-evidence-lab"
OUTPUT = LAB / "generated" / "correlation-proof.json"


def test_reference_lab_generated_output_is_current() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_reference_evidence_lab.py"), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


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
    assert proof["analysis"]["status"] == "complete"


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
