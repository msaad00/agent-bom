"""Characterization golden for the Terraform and Kubernetes misconfig scanners.

The corpus under ``tests/fixtures/iac_golden`` holds every Terraform/Kubernetes
input the scanner test suites feed these scanners plus a synthetic corpus that
fires every rule ID. The golden pins the exact findings (all fields, in order),
so structural refactors of the scanners must reproduce them byte for byte.

Regenerate only for an intended behavior change:
``REGEN_IAC_GOLDEN=1 pytest tests/test_iac_scanner_golden.py``.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from pathlib import Path
from typing import Any

from agent_bom.iac.kubernetes import scan_k8s_manifest
from agent_bom.iac.terraform_security import scan_terraform_security

FIXTURES = Path(__file__).parent / "fixtures" / "iac_golden"
GOLDEN = FIXTURES / "golden.json"
SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "iac"


def _serialize(finding: Any) -> dict[str, Any]:
    data = dataclasses.asdict(finding)
    data["file_path"] = Path(data["file_path"]).relative_to(FIXTURES).as_posix()
    if data["resource_type"] is not None:
        data["resource_type"] = str(data["resource_type"])
    return data


def _stable_cross_doc_tail(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # K8S-021 is emitted by iterating a set of Deployment names, so its order is
    # hash-seed dependent; everything else is order-pinned.
    head = [f for f in findings if f["rule_id"] != "K8S-021"]
    tail = sorted((f for f in findings if f["rule_id"] == "K8S-021"), key=lambda f: f["message"])
    return head + tail


def _collect() -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    for path in sorted((FIXTURES / "terraform").glob("*.tf")):
        results[f"terraform/{path.name}"] = [_serialize(f) for f in scan_terraform_security(path)]
    for path in sorted((FIXTURES / "kubernetes").glob("*.yaml")):
        results[f"kubernetes/{path.name}"] = _stable_cross_doc_tail([_serialize(f) for f in scan_k8s_manifest(path)])
    return results


def _declared_rule_ids(module: str, pattern: str) -> set[str]:
    text = "".join(p.read_text() for p in SRC.glob(f"{module}*.py"))
    return set(re.findall(pattern, text))


def test_iac_scanner_golden_matches() -> None:
    actual = _collect()
    if os.environ.get("REGEN_IAC_GOLDEN") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=1, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert sorted(actual) == sorted(expected)
    for name in expected:
        assert actual[name] == expected[name], name


def test_iac_golden_corpus_fires_every_rule() -> None:
    expected = json.loads(GOLDEN.read_text())
    fired = {f["rule_id"] for findings in expected.values() for f in findings}
    tf_rules = _declared_rule_ids("terraform_security", r'rule_id="(TF-SEC-\d+)"')
    k8s_rules = _declared_rule_ids("kubernetes", r'rule_id="(K8S-\d+)"')
    assert len(tf_rules) == 50
    assert len(k8s_rules) == 32
    assert tf_rules | k8s_rules <= fired
    assert len(expected) >= 140
