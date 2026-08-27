"""Release-blocking scale contracts for public scan evidence projections.

These are intentionally absolute budgets rather than comparisons with a Git
baseline.  The limits leave substantial headroom over developer-workstation
measurements while still catching accidental quadratic work, repeated whole
document sanitization, and unbounded projection regressions at a realistic
2,000-item release size.
"""

from __future__ import annotations

import csv
import gc
import io
import json
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypeVar

import pytest

from agent_bom.api.routes.scan import _redact_scan_result_for_response
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output import to_csv, to_cyclonedx, to_html, to_markdown, to_spdx
from agent_bom.output.spdx2_fmt import to_spdx2

pytestmark = [pytest.mark.slow, pytest.mark.output_performance]

_ITEM_COUNT = 2_000
_SECRET = "ghp_" + "s" * 36
_EMAIL = "scale.sentinel@example.invalid"
_CREDENTIAL_URL = "postgresql://scale-user:scale-password@db.internal/release"

# Absolute wall-clock ceilings with generous shared-CI variance.  The
# correctness assertions below prevent an implementation from meeting them by
# dropping rows, relationships, or redaction work.
_HUMAN_EXPORT_BUDGETS_S = {"csv": 5.0, "markdown": 8.0, "html": 8.0}
_INTEROP_EXPORT_BUDGETS_S = {"cyclonedx": 4.0, "spdx3": 4.0, "spdx2": 2.0}
_API_PROJECTION_BUDGET_S = 2.0

T = TypeVar("T")


def _timed(call: Callable[[], T]) -> tuple[T, float]:
    """Measure one warmed import path without unrelated prior-test garbage."""
    gc.collect()
    started = time.perf_counter()
    result = call()
    return result, time.perf_counter() - started


def _package(index: int, *, sensitive: bool = False) -> Package:
    description = f"Leaked {_SECRET} owned by {_EMAIL} at {_CREDENTIAL_URL}" if sensitive else f"Synthetic vulnerability evidence {index}"
    vulnerability = Vulnerability(
        id=f"CVE-2026-{20_000 + index}",
        summary=description,
        severity=(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)[index % 4],
        cvss_score=9.8 - (index % 4) * 2.0,
        fixed_version=f"1.{index % 10}.1",
    )
    return Package(
        name=f"scale-package-{index}",
        version=f"1.{index % 10}.0",
        ecosystem=("pypi", "npm", "go", "cargo")[index % 4],
        vulnerabilities=[vulnerability],
    )


@pytest.fixture(scope="module")
def human_export_report() -> tuple[AIBOMReport, list[BlastRadius]]:
    radii: list[BlastRadius] = []
    for index in range(_ITEM_COUNT):
        package = _package(index, sensitive=index == _ITEM_COUNT - 1)
        radii.append(
            BlastRadius(
                vulnerability=package.vulnerabilities[0],
                package=package,
                affected_servers=[],
                affected_agents=[],
                exposed_credentials=[],
                exposed_tools=[],
            )
        )
    return (
        AIBOMReport(
            blast_radii=radii,
            generated_at=datetime(2026, 8, 27, tzinfo=timezone.utc),
            tool_version="0.0.0-test",
        ),
        radii,
    )


@pytest.fixture(scope="module")
def interop_export_report() -> AIBOMReport:
    packages = [_package(index, sensitive=index == _ITEM_COUNT - 1) for index in range(_ITEM_COUNT)]
    server = MCPServer(
        name="scale-server",
        command="python",
        args=["server.py"],
        packages=packages,
    )
    agent = Agent(
        name="scale-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/scale-agent.json",
        mcp_servers=[server],
    )
    return AIBOMReport(
        agents=[agent],
        generated_at=datetime(2026, 8, 27, tzinfo=timezone.utc),
        tool_version="0.0.0-test",
    )


def _api_finding(index: int) -> dict[str, object]:
    sensitive = index == _ITEM_COUNT - 1
    description = f"Leaked {_SECRET} owned by {_EMAIL} at {_CREDENTIAL_URL}" if sensitive else f"Synthetic API evidence {index}"
    return {
        "id": f"finding-{index}",
        "canonical_id": f"finding-{index}",
        "finding_type": "CVE",
        "source": "SBOM",
        "severity": "high",
        "title": description,
        "description": description,
        "asset": {
            "name": f"scale-package-{index}",
            "asset_type": "package",
            "identifier": f"pkg:pypi/scale-package-{index}@1.0.0",
            "location": _CREDENTIAL_URL if sensitive else f"/tmp/scale-package-{index}",
            "stable_id": f"asset-{index}",
        },
        "cve_id": f"CVE-2026-{20_000 + index}",
        "status": "open",
        "first_seen": "2026-08-27T00:00:00Z",
        "last_observed": "2026-08-27T00:01:00Z",
        "fixed_version": "1.0.1",
        "evidence": {"raw": description},
    }


def _assert_within_budget(name: str, elapsed: float, budgets: dict[str, float]) -> None:
    budget = budgets[name]
    assert elapsed < budget, f"{name} rendered {_ITEM_COUNT:,} items in {elapsed:.3f}s (budget {budget:.1f}s)"


def test_human_exporters_hold_2000_finding_scale_and_redaction_contract(
    human_export_report: tuple[AIBOMReport, list[BlastRadius]],
) -> None:
    report, radii = human_export_report
    rendered: dict[str, str] = {}
    elapsed: dict[str, float] = {}

    rendered["csv"], elapsed["csv"] = _timed(lambda: to_csv(report, radii))
    rendered["markdown"], elapsed["markdown"] = _timed(lambda: to_markdown(report, radii))
    rendered["html"], elapsed["html"] = _timed(lambda: to_html(report, radii))

    csv_rows = list(csv.DictReader(io.StringIO(rendered["csv"].lstrip("\ufeff"))))
    assert len(csv_rows) == _ITEM_COUNT
    assert csv_rows[-1]["cve_id"] == f"CVE-2026-{20_000 + _ITEM_COUNT - 1}"
    assert rendered["html"].count("data-cvss=") == _ITEM_COUNT
    assert f"CVE-2026-{20_000 + _ITEM_COUNT - 1}" in rendered["markdown"]
    for name, output in rendered.items():
        assert _SECRET not in output
        assert _EMAIL not in output
        assert _CREDENTIAL_URL not in output
        _assert_within_budget(name, elapsed[name], _HUMAN_EXPORT_BUDGETS_S)

    # Exporters must detach their render view rather than mutate durable scan evidence.
    assert _SECRET in radii[-1].vulnerability.summary


def test_interop_exports_hold_2000_package_scale_and_topology_contract(
    interop_export_report: AIBOMReport,
) -> None:
    documents: dict[str, dict[str, object]] = {}
    elapsed: dict[str, float] = {}

    documents["cyclonedx"], elapsed["cyclonedx"] = _timed(lambda: to_cyclonedx(interop_export_report))
    documents["spdx3"], elapsed["spdx3"] = _timed(lambda: to_spdx(interop_export_report))
    documents["spdx2"], elapsed["spdx2"] = _timed(lambda: to_spdx2(interop_export_report))

    cdx_components = documents["cyclonedx"]["components"]
    assert isinstance(cdx_components, list)
    cdx_refs = {component["bom-ref"] for component in cdx_components if isinstance(component, dict)}
    cdx_libraries = [component for component in cdx_components if isinstance(component, dict) and component.get("type") == "library"]
    assert len(cdx_libraries) == _ITEM_COUNT
    assert len(cdx_refs) == len(cdx_components)
    for dependency in documents["cyclonedx"]["dependencies"]:
        assert dependency["ref"] in cdx_refs
        assert set(dependency.get("dependsOn", ())) <= cdx_refs

    spdx3_graph = documents["spdx3"]["@graph"]
    assert isinstance(spdx3_graph, list)
    spdx3_ids = {element["spdxId"] for element in spdx3_graph if isinstance(element, dict) and isinstance(element.get("spdxId"), str)}
    assert len(spdx3_ids) == len(spdx3_graph) - 1  # only the shared CreationInfo blank node has no spdxId
    # SPDX 3 models the agent and MCP server as software packages too.
    assert sum(element.get("type") == "software_Package" for element in spdx3_graph if isinstance(element, dict)) == _ITEM_COUNT + 2
    spdx3_document = next(element for element in spdx3_graph if isinstance(element, dict) and element.get("type") == "SpdxDocument")
    assert set(spdx3_document["rootElement"]) <= spdx3_ids
    for relationship in (
        element
        for element in spdx3_graph
        if isinstance(element, dict) and isinstance(element.get("from"), str) and isinstance(element.get("to"), list)
    ):
        assert relationship["from"] in spdx3_ids
        assert set(relationship["to"]) <= spdx3_ids

    spdx2_packages = documents["spdx2"]["packages"]
    assert isinstance(spdx2_packages, list)
    spdx2_ids = {package["SPDXID"] for package in spdx2_packages if isinstance(package, dict)}
    assert len(spdx2_packages) == _ITEM_COUNT + 2  # one agent and one MCP server
    assert len(spdx2_ids) == len(spdx2_packages)
    valid_spdx2_refs = spdx2_ids | {"SPDXRef-DOCUMENT"}
    for relationship in documents["spdx2"]["relationships"]:
        assert relationship["spdxElementId"] in valid_spdx2_refs
        assert relationship["relatedSpdxElement"] in valid_spdx2_refs

    for name, document in documents.items():
        encoded = json.dumps(document)
        assert _SECRET not in encoded
        assert _EMAIL not in encoded
        assert _CREDENTIAL_URL not in encoded
        _assert_within_budget(name, elapsed[name], _INTEROP_EXPORT_BUDGETS_S)

    assert _SECRET in interop_export_report.agents[0].mcp_servers[0].packages[-1].vulnerabilities[0].summary


def test_api_result_projection_holds_2000_finding_scale_and_redaction_contract() -> None:
    durable = {
        "scan_id": "scale-scan",
        "summary": {"total_findings": _ITEM_COUNT},
        "findings": [_api_finding(index) for index in range(_ITEM_COUNT)],
    }

    projected, elapsed = _timed(lambda: _redact_scan_result_for_response(durable))

    assert projected is not None
    projected_findings = projected["findings"]
    assert isinstance(projected_findings, list)
    assert len(projected_findings) == _ITEM_COUNT
    assert projected_findings[-1]["id"] == f"finding-{_ITEM_COUNT - 1}"
    assert "location" not in projected_findings[-1]["asset"]
    encoded = json.dumps(projected)
    assert _SECRET not in encoded
    assert _EMAIL not in encoded
    assert _CREDENTIAL_URL not in encoded
    assert _SECRET in durable["findings"][-1]["description"]
    assert elapsed < _API_PROJECTION_BUDGET_S, (
        f"API projected {_ITEM_COUNT:,} findings in {elapsed:.3f}s (budget {_API_PROJECTION_BUDGET_S:.1f}s)"
    )
