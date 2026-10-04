#!/usr/bin/env python3
"""Reproduce component investigation and a real offline dependency rescan.

Cloud topology/check inputs are synthetic; package parsing and pinned advisory
matching execute production code. No cloud credentials or cloud APIs are used.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.api.graph_store import SQLiteGraphStore  # noqa: E402
from agent_bom.api.inventory_service import build_asset_detail  # noqa: E402
from agent_bom.graph import EntityType, UnifiedNode  # noqa: E402
from agent_bom.graph.builder import build_unified_graph_from_report  # noqa: E402
from agent_bom.mcp_tools.inventory import inventory_asset_impl  # noqa: E402
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package  # noqa: E402
from agent_bom.output import to_cyclonedx, to_spdx, to_spdx2  # noqa: E402
from agent_bom.parsers import scan_project_directory  # noqa: E402
from agent_bom.scanners.package_scan import default_scan_options, scan_packages  # noqa: E402

ADVISORY = "CVE-2023-4863"
TENANT = "connected-bom-example"


def cloud_inputs() -> list[dict[str, Any]]:
    """Equal display names are deliberate; native provider identities differ."""
    return [
        {
            "provider": "aws",
            "status": "ok",
            "account_id": "example-account",
            "region": "us-east-1",
            "evidence_origin": "synthetic-example",
            "lambda_functions": [
                {
                    "name": "shared-service",
                    "arn": "arn:aws:lambda:us-east-1:example-account:function:shared-service",
                    "tags": {"environment": "example"},
                }
            ],
        },
        {
            "provider": "azure",
            "status": "ok",
            "subscription_id": "example-subscription",
            "account_id": "example-subscription",
            "evidence_origin": "synthetic-example",
            "key_vaults": [
                {
                    "name": "shared-service",
                    "id": "/subscriptions/example-subscription/resourceGroups/example/providers/Microsoft.KeyVault/vaults/shared-service",
                    "tags": {"environment": "example"},
                }
            ],
        },
        {
            "provider": "gcp",
            "status": "ok",
            "project_id": "example-project",
            "account_id": "example-project",
            "evidence_origin": "synthetic-example",
            "cloud_sql_instances": [
                {"name": "shared-service", "id": "projects/example-project/instances/shared-service", "labels": {"environment": "example"}}
            ],
        },
    ]


async def scan_version(version: str) -> tuple[list[Package], str]:
    manifest = f"Pillow=={version}\n"
    with tempfile.TemporaryDirectory(prefix="agent-bom-connected-input-") as directory:
        root = Path(directory)
        (root / "requirements.txt").write_text(manifest)
        discovered = scan_project_directory(root, max_depth=1)
        packages = [package for path in sorted(discovered, key=str) for package in discovered[path]]
        if len(packages) != 1 or packages[0].version != version:
            raise RuntimeError("Dependency parser did not retain the selected version")
        await scan_packages(packages, options=default_scan_options(offline=True, demo_advisories=True, project_dir=str(root)))
    return packages, hashlib.sha256(manifest.encode()).hexdigest()


def export_boms(output: Path, label: str, packages: list[Package]) -> list[str]:
    """Export the actual parsed/scanned packages alongside labeled cloud inputs."""
    report = AIBOMReport(
        agents=[
            Agent(
                name="example-repository",
                agent_type=AgentType.CUSTOM,
                config_path="example-repository",
                mcp_servers=[MCPServer(name="repo-deps:root", command="", packages=packages)],
            )
        ],
        cloud_inventory_data=cloud_inputs(),
        scan_sources=["repo-lockfiles", "synthetic-cloud-model"],
    )
    artifacts = []
    for name, exporter in (("cyclonedx", to_cyclonedx), ("spdx", to_spdx), ("spdx2", to_spdx2)):
        filename = f"{label}.{name}.json"
        (output / filename).write_text(json.dumps(exporter(report), indent=2) + "\n")
        artifacts.append(filename)
    return artifacts


async def prove(output: Path) -> dict[str, Any]:
    if output.exists() and any(output.iterdir()):
        raise ValueError("Choose a new or empty output directory; existing evidence is preserved")
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    db = output / "graph.db"
    store = SQLiteGraphStore(db)
    receipts: list[dict[str, Any]] = []
    selected: dict[str, str] = {}
    for label, version in (("before", "9.0.0"), ("after", "10.0.1")):
        packages, digest = await scan_version(version)
        bom_artifacts = export_boms(output, label, packages)
        report = {
            "scan_sources": ["repo-lockfiles", "synthetic-cloud-model"],
            "agents": [
                {
                    "name": "example-repository",
                    "source": "repo-lockfiles",
                    "config_path": "example-repository",
                    "mcp_servers": [
                        {
                            "name": "repo-deps:root",
                            "surface": "filesystem",
                            "packages": [json.loads(json.dumps(asdict(package), default=str)) for package in packages],
                        }
                    ],
                }
            ],
            "cloud_inventory": cloud_inputs(),
            "gcp_cis_benchmark": {
                "project_id": "example-project",
                "checks": [
                    {
                        "check_id": "example-control",
                        "title": "Modeled failed configuration check",
                        "status": "FAIL",
                        "resource_ids": ["projects/example-project/instances/shared-service"],
                        "severity": "high",
                        "evidence": "Synthetic configuration evidence; no provider evaluation was performed.",
                    }
                ],
            },
        }
        graph = build_unified_graph_from_report(report, scan_id=f"connected-{label}", tenant_id=TENANT)
        graph.add_node(
            UnifiedNode(
                id="model:disconnected", entity_type=EntityType.MODEL, label="Disconnected model", data_sources=["synthetic-cloud-model"]
            )
        )
        store.save_graph(graph)
        # Reopen the database: this evidence must survive the writer's lifetime.
        reader = SQLiteGraphStore(db)
        package = next(node for node in graph.nodes.values() if node.entity_type == EntityType.PACKAGE)
        selected[label] = package.id
        detail = await build_asset_detail(store=reader, tenant_id=TENANT, asset_id=package.id, scan_id=graph.scan_id, limit=1)
        if detail is None:
            raise RuntimeError("Persisted component was not found")
        pages = [detail]
        while pages[-1]["next_cursor"]:
            if len(pages) >= 10:
                raise RuntimeError("Example exceeded its bounded page budget")
            next_page = await build_asset_detail(
                store=reader,
                tenant_id=TENANT,
                asset_id=package.id,
                scan_id=graph.scan_id,
                limit=1,
                cursor=pages[-1]["next_cursor"],
                snapshot_generation=detail["snapshot_generation"],
            )
            if next_page is None:
                raise RuntimeError("Component disappeared during continuation")
            pages.append(next_page)
        mcp = json.loads(await inventory_asset_impl(asset_id=package.id, scan_id=graph.scan_id, limit=1, _get_graph_store=lambda: reader))
        if mcp != detail:
            raise RuntimeError("MCP and inventory service returned different component evidence")
        if await build_asset_detail(store=reader, tenant_id="unrelated-tenant", asset_id=package.id, scan_id=graph.scan_id) is not None:
            raise RuntimeError("Component crossed the tenant boundary")
        equal_names = [node for node in graph.nodes.values() if node.attributes.get("resource_name") == "shared-service"]
        if len({node.id for node in equal_names}) != 3:
            raise RuntimeError("Same-name provider resources were merged or lost")
        disconnected = await build_asset_detail(store=reader, tenant_id=TENANT, asset_id="model:disconnected", scan_id=graph.scan_id)
        if disconnected is None or disconnected["edges_in"] or disconnected["edges_out"]:
            raise RuntimeError("Disconnected component acquired a synthetic chain")
        findings = sorted({node["id"] for page in pages for node in page["nodes"] if node["entity_type"] == "vulnerability"})
        if (f"vuln:{ADVISORY}" in findings) != (label == "before"):
            raise RuntimeError("Changed-input rescan did not change the pinned advisory finding")
        cloud = next(node for node in equal_names if node.dimensions.cloud_provider == "gcp")
        controls = await build_asset_detail(store=reader, tenant_id=TENANT, asset_id=cloud.id, scan_id=graph.scan_id)
        if controls is None or not any(node["attributes"].get("evaluation_status") == "fail" for node in controls["nodes"]):
            raise RuntimeError("Recorded control evidence lost its explicit result")
        (output / f"{label}-graph.json").write_text(json.dumps(graph.to_dict(), indent=2))
        (output / f"{label}-component.json").write_text(json.dumps(pages, indent=2))
        (output / f"{label}-controls.json").write_text(json.dumps(controls, indent=2))
        receipts.append(
            {
                "snapshot": graph.scan_id,
                "package_version": version,
                "input_sha256": digest,
                "component_id": package.id,
                "generation": detail["snapshot_generation"],
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
                "relationship_pages": len(pages),
                "linked_findings": findings,
                "mcp_service_parity": True,
                "same_name_cloud_resources": len(equal_names),
                "tenant_isolation": True,
                "bom_artifacts": bom_artifacts,
            }
        )
    delta = store.diff_snapshots("connected-before", "connected-after", tenant_id=TENANT)
    (output / "rescan-diff.json").write_text(json.dumps(delta, indent=2))
    result = {
        "schema_version": "agent-bom.connected-workflow-proof.v1",
        "mode": "offline_scanner_and_synthetic_cloud_topology",
        "receipts": receipts,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "limits": [
            "One pinned advisory regression, not broad vulnerability accuracy or a clean verdict.",
            "Cloud topology and check results are synthetic; no cloud API authentication is tested.",
            "Package version changes produce distinct components; this is a changed-input rescan, not a deployment fix.",
            "Bounded local SQLite fixture; not enterprise scale or independent attestation.",
            "MCP tool implementation and shared REST service are compared; wire transport is tested separately.",
        ],
    }
    (output / "proof.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    # Bind only this process's MCP reader; no credentials or remote state needed.
    os.environ["AGENT_BOM_MCP_TENANT_ID"] = TENANT
    result = asyncio.run(prove(args.output_dir.resolve()))
    print(json.dumps({"artifact": str(args.output_dir.resolve() / "proof.json"), "receipts": result["receipts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
