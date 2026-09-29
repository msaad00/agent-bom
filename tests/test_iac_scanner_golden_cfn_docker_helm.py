"""Characterization golden for the CloudFormation, Dockerfile and Helm values scanners.

The corpus under ``tests/fixtures/iac_golden/{cloudformation,dockerfile,
dockerfile_dockerignore,helm}`` holds every input the existing test suites feed
these scanners plus synthetic files that fire every rule ID and exercise
malformed input. The golden pins the exact findings (all fields, in order) and
any exception raised, so structural refactors must reproduce them byte for byte.

Regenerate only for an intended behavior change:
``REGEN_IAC_GOLDEN=1 pytest tests/test_iac_scanner_golden_cfn_docker_helm.py``.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_bom.iac.cloudformation import scan_cloudformation
from agent_bom.iac.dockerfile import scan_dockerfile
from agent_bom.iac.helm import scan_values_yaml

FIXTURES = Path(__file__).parent / "fixtures" / "iac_golden"
GOLDEN = FIXTURES / "golden_cfn_docker_helm.json"
SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "iac"

_CORPORA: tuple[tuple[str, str, Callable[[Any], list[Any]]], ...] = (
    ("cloudformation", "*", scan_cloudformation),
    ("dockerfile", "*.Dockerfile", scan_dockerfile),
    ("dockerfile_dockerignore", "*.Dockerfile", scan_dockerfile),
    ("helm", "*.yaml", scan_values_yaml),
)


def _serialize(finding: Any) -> dict[str, Any]:
    data = dataclasses.asdict(finding)
    data["file_path"] = Path(data["file_path"]).relative_to(FIXTURES).as_posix()
    if data["resource_type"] is not None:
        data["resource_type"] = str(data["resource_type"])
    return data


def _stable_set_order(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # HELM-013 iterates a set of admin-password keys, so the relative order of
    # those findings depends on the hash seed; every other finding is pinned.
    slots = [i for i, f in enumerate(findings) if f["rule_id"] == "HELM-013"]
    ordered = sorted((findings[i] for i in slots), key=lambda f: f["title"])
    result = list(findings)
    for slot, finding in zip(slots, ordered):
        result[slot] = finding
    return result


def _run(scanner: Callable[[Any], list[Any]], path: Path) -> Any:
    try:
        return _stable_set_order([_serialize(f) for f in scanner(path)])
    except Exception as exc:  # noqa: BLE001 - malformed input behavior is part of the contract
        return {"exception": type(exc).__name__, "message": str(exc)}


def _collect() -> dict[str, Any]:
    results: dict[str, Any] = {}
    for corpus, pattern, scanner in _CORPORA:
        for path in sorted((FIXTURES / corpus).glob(pattern)):
            if path.name.startswith("."):
                continue
            results[f"{corpus}/{path.name}"] = _run(scanner, path)
    return results


def _declared_rule_ids(module: str, pattern: str) -> set[str]:
    text = "".join(p.read_text() for p in SRC.glob(f"{module}*.py"))
    return set(re.findall(pattern, text))


def test_cfn_docker_helm_golden_matches() -> None:
    actual = _collect()
    if os.environ.get("REGEN_IAC_GOLDEN") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=1, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert sorted(actual) == sorted(expected)
    for name in expected:
        assert actual[name] == expected[name], name


def test_cfn_docker_helm_corpus_fires_every_rule() -> None:
    expected = json.loads(GOLDEN.read_text())
    fired = {f["rule_id"] for findings in expected.values() if isinstance(findings, list) for f in findings}
    cfn_rules = _declared_rule_ids("cloudformation", r'rule_id="(CFN-\d+)"')
    docker_rules = _declared_rule_ids("dockerfile", r'rule_id="(DOCKER-\d+)"')
    helm_rules = _declared_rule_ids("helm", r'rule_id="(HELM-\d+)"') - {"HELM-001", "HELM-002"}
    assert len(cfn_rules) == 20
    assert len(docker_rules) == 21  # DOCKER-016 is documented but never emitted
    assert len(helm_rules) == 13
    assert cfn_rules | docker_rules | helm_rules <= fired
    assert any(isinstance(v, dict) and "exception" in v for v in expected.values())
    assert len(expected) >= 100
