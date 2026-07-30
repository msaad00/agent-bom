"""Prevent CIS remediation overrides drifting away from live controls."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

from agent_bom.cloud.cis_remediation import (
    _OVERRIDES,
    _VERIFIED_CLI_CONTROLS,
    CISControlIdentity,
    CISRemediationOverride,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CLOUD_MODULES = {
    "aws": _REPO_ROOT / "src/agent_bom/cloud/aws_cis_benchmark.py",
    "azure": _REPO_ROOT / "src/agent_bom/cloud/azure_cis_benchmark.py",
    "gcp": _REPO_ROOT / "src/agent_bom/cloud/gcp_cis_benchmark.py",
    "snowflake": _REPO_ROOT / "src/agent_bom/cloud/snowflake_cis_benchmark.py",
}


def _literal_string(node: ast.expr | None, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _catalog_identities(cloud: str, path: Path) -> list[CISControlIdentity]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants: dict[str, str] = {}
    benchmark_version = ""

    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = _literal_string(node.value, constants)
            if value is not None:
                constants[node.targets[0].id] = value
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and child.target.id == "benchmark_version":
                    benchmark_version = _literal_string(child.value, constants) or ""

    identities: list[CISControlIdentity] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "CISCheckResult"):
            continue
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        check_id = _literal_string(keywords.get("check_id"), constants)
        title = _literal_string(keywords.get("title"), constants)
        cis_section = _literal_string(keywords.get("cis_section"), constants)
        if check_id is not None and title is not None and cis_section is not None:
            identities.append(
                CISControlIdentity(
                    cloud=cloud,
                    benchmark_version=benchmark_version,
                    check_id=check_id,
                    title=title,
                    cis_section=cis_section,
                )
            )
    return identities


def test_each_override_matches_exactly_one_live_catalog_control() -> None:
    live = Counter(identity for cloud, path in _CLOUD_MODULES.items() for identity in _catalog_identities(cloud, path))

    assert _OVERRIDES
    for identity, override in _OVERRIDES.items():
        assert isinstance(identity, CISControlIdentity)
        assert isinstance(override, CISRemediationOverride)
        assert live[identity] == 1, f"override is stale or ambiguous: {identity}"


def test_pr1_has_no_verified_cli_mutations() -> None:
    assert _VERIFIED_CLI_CONTROLS == frozenset()
    for override in _OVERRIDES.values():
        assert override.fix_cli is None
        assert override.effort == "manual"
        assert override.requires_human_review is True
