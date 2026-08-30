#!/usr/bin/env python3
"""Generate the credential-free correlated evidence reference lab proof."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.api.graph_store import SQLiteGraphStore  # noqa: E402
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode  # noqa: E402
from agent_bom.graph.correlation_service import CorrelationRequest, GraphCorrelationService  # noqa: E402
from agent_bom.parsers import scan_project_directory  # noqa: E402
from agent_bom.scanners.package_scan import default_scan_options, scan_packages  # noqa: E402

LAB = ROOT / "examples" / "reference-evidence-lab"
OUTPUT = LAB / "generated" / "correlation-proof.json"
TENANT = "reference-lab"
CORRELATION_ID = "reference-evidence-correlation-v1"
CREATED = datetime(2026, 8, 30, 4, 0, tzinfo=timezone.utc)
IMAGE_DIGEST = "sha256:7d3e21c47d244111d7502503e9868ce01f2dfd77f0d71d876a3a8da1f477d58a"
PURL = "pkg:pypi/pillow@9.0.0"
ADVISORY = "CVE-2023-4863"


def _timestamp(index: int) -> str:
    return (CREATED + timedelta(minutes=index)).isoformat()


def _node(
    node_id: str,
    entity_type: EntityType,
    label: str,
    *,
    source: str,
    attributes: dict[str, Any],
    index: int,
    severity: str = "",
    risk_score: float = 0.0,
) -> UnifiedNode:
    observed = _timestamp(index)
    return UnifiedNode(
        id=node_id,
        entity_type=entity_type,
        label=label,
        attributes=attributes,
        data_sources=[source],
        severity=severity,
        risk_score=risk_score,
        first_seen=observed,
        last_seen=observed,
    )


def _edge(
    source: str,
    target: str,
    relationship: RelationshipType,
    *,
    scan_id: str,
    source_kind: str,
    evidence_tier: str,
    index: int,
    runtime_state: str = "not_observed",
) -> UnifiedEdge:
    observed = _timestamp(index)
    evidence: dict[str, Any] = {
        "source_kind": source_kind,
        "evidence_tier": evidence_tier,
    }
    if evidence_tier == "modeled_infrastructure":
        evidence["modeled"] = True
    if runtime_state != "not_observed":
        evidence["runtime_observed"] = True
        evidence["runtime_observed_state"] = runtime_state
    return UnifiedEdge(
        source=source,
        target=target,
        relationship=relationship,
        source_scan_id=scan_id,
        source_run_id=scan_id,
        first_seen=observed,
        last_seen=observed,
        valid_from=observed,
        evidence=evidence,
        provenance={"source": source_kind, "artifact": str(LAB.relative_to(ROOT))},
        confidence=1.0,
        traversable=True,
    )


def _graph(scan_id: str, index: int) -> UnifiedGraph:
    return UnifiedGraph(scan_id=scan_id, tenant_id=TENANT, created_at=_timestamp(index))


async def _scanner_evidence() -> dict[str, Any]:
    discovered = scan_project_directory(LAB, max_depth=1)
    packages = [package for directory in sorted(discovered, key=str) for package in discovered[directory]]
    pillow = next((package for package in packages if package.name.lower() == "pillow" and package.version == "9.0.0"), None)
    if pillow is None:
        raise RuntimeError("reference lab parser did not discover Pillow 9.0.0")
    await scan_packages(
        packages,
        options=default_scan_options(
            offline=True,
            demo_advisories=True,
            project_dir=str(LAB),
        ),
    )
    vulnerability = next((item for item in pillow.vulnerabilities if item.id == ADVISORY), None)
    if vulnerability is None:
        raise RuntimeError("reference lab scanner did not match the pinned CVE-2023-4863 advisory")
    return {
        "parser": "agent_bom.parsers.scan_project_directory",
        "scanner": "agent_bom.scanners.package_scan.scan_packages",
        "mode": "offline_bundled_pinned_advisory",
        "manifest": "examples/reference-evidence-lab/requirements.txt",
        "package": PURL,
        "advisory": vulnerability.id,
        "severity": vulnerability.severity.value,
        "cvss_score": vulnerability.cvss_score,
        "is_kev": vulnerability.is_kev,
    }


def _snapshots() -> list[UnifiedGraph]:
    repo = _graph("reference-repository-scan", 0)
    repo.add_node(
        _node(
            "source:requirements",
            EntityType.SOURCE_FILE,
            "requirements.txt",
            source="repository_parser",
            attributes={
                "repository_commit": "a9f53db346d078d26f8f53c6cc6ee98e3230f284",
                "repository_path": "requirements.txt",
            },
            index=0,
        )
    )
    repo.add_node(
        _node(
            "package:repo:pillow",
            EntityType.PACKAGE,
            "pillow@9.0.0",
            source="repository_parser",
            attributes={"purl": PURL, "canonical_id": PURL},
            index=0,
        )
    )
    repo.add_edge(
        _edge(
            "source:requirements",
            "package:repo:pillow",
            RelationshipType.IMPORTS,
            scan_id=repo.scan_id,
            source_kind="repository_parser",
            evidence_tier="static_evidence",
            index=0,
        )
    )

    sbom = _graph("reference-image-sbom-scan", 1)
    sbom.add_node(
        _node(
            "container:sbom:reference-api",
            EntityType.CONTAINER,
            f"reference-evidence-api@{IMAGE_DIGEST[:19]}…",
            source="cyclonedx_sbom",
            attributes={"image_digest": IMAGE_DIGEST, "sbom": "sbom.cdx.json"},
            index=1,
        )
    )
    sbom.add_node(
        _node(
            "package:sbom:pillow",
            EntityType.PACKAGE,
            "pillow@9.0.0",
            source="cyclonedx_sbom",
            attributes={"purl": PURL, "canonical_id": PURL},
            index=1,
            severity="high",
            risk_score=8.8,
        )
    )
    sbom.add_node(
        _node(
            "vulnerability:sbom:cve-2023-4863",
            EntityType.VULNERABILITY,
            ADVISORY,
            source="bundled_advisory_scanner",
            attributes={"canonical_id": ADVISORY, "finding_id": "reference-finding-cve-2023-4863", "is_kev": True},
            index=1,
            severity="high",
            risk_score=8.8,
        )
    )
    sbom.add_edge(
        _edge(
            "container:sbom:reference-api",
            "package:sbom:pillow",
            RelationshipType.CONTAINS,
            scan_id=sbom.scan_id,
            source_kind="cyclonedx_sbom",
            evidence_tier="static_evidence",
            index=1,
        )
    )
    sbom.add_edge(
        _edge(
            "package:sbom:pillow",
            "vulnerability:sbom:cve-2023-4863",
            RelationshipType.VULNERABLE_TO,
            scan_id=sbom.scan_id,
            source_kind="bundled_advisory_scanner",
            evidence_tier="static_evidence",
            index=1,
        )
    )

    iac = _graph("reference-kubernetes-iac-scan", 2)
    iac.add_node(
        _node(
            "service:reference-api",
            EntityType.SERVER,
            "Public reference API service",
            source="kubernetes_iac",
            attributes={"canonical_id": "kubernetes-uid:9ba1b7ae-3bd2-5cb6-951a-5935ad4fc3a1", "internet_exposed": True, "modeled": True},
            index=2,
            severity="high",
            risk_score=8.0,
        )
    )
    iac.add_node(
        _node(
            "workload:reference-api",
            EntityType.AGENT,
            "reference-evidence-api workload",
            source="kubernetes_iac",
            attributes={
                "canonical_id": "kubernetes-uid:495b5f42-47ae-51f8-918f-5f86cb1e9ad5",
                "runtime_id": "reference-evidence-workload",
                "modeled": True,
            },
            index=2,
        )
    )
    iac.add_node(
        _node(
            "container:iac:reference-api",
            EntityType.CONTAINER,
            f"reference-evidence-api@{IMAGE_DIGEST[:19]}…",
            source="kubernetes_iac",
            attributes={"image_digest": IMAGE_DIGEST, "modeled": True},
            index=2,
        )
    )
    iac.add_edge(
        _edge(
            "service:reference-api",
            "workload:reference-api",
            RelationshipType.USES,
            scan_id=iac.scan_id,
            source_kind="kubernetes_iac",
            evidence_tier="modeled_infrastructure",
            index=2,
        )
    )
    iac.add_edge(
        _edge(
            "workload:reference-api",
            "container:iac:reference-api",
            RelationshipType.CONTAINS,
            scan_id=iac.scan_id,
            source_kind="kubernetes_iac",
            evidence_tier="modeled_infrastructure",
            index=2,
        )
    )

    mcp = _graph("reference-mcp-config-scan", 3)
    mcp.add_node(
        _node(
            "vulnerability:mcp:cve-2023-4863",
            EntityType.VULNERABILITY,
            ADVISORY,
            source="mcp_config",
            attributes={"canonical_id": ADVISORY},
            index=3,
            severity="high",
            risk_score=8.8,
        )
    )
    mcp.add_node(
        _node(
            "tool:mcp:render-untrusted-image",
            EntityType.TOOL,
            "render_untrusted_image",
            source="mcp_config",
            attributes={
                "canonical_id": "mcp-tool:reference-lab:render-untrusted-image",
                "stable_id": "mcp-tool:reference-lab:render-untrusted-image",
                "capabilities": ["file_read", "image_decode"],
            },
            index=3,
            severity="high",
            risk_score=8.0,
        )
    )
    mcp.add_edge(
        _edge(
            "vulnerability:mcp:cve-2023-4863",
            "tool:mcp:render-untrusted-image",
            RelationshipType.EXPLOITABLE_VIA,
            scan_id=mcp.scan_id,
            source_kind="mcp_config",
            evidence_tier="static_evidence",
            index=3,
        )
    )

    runtime = _graph("reference-runtime-observation", 4)
    runtime.add_node(
        _node(
            "tool:runtime:render-untrusted-image",
            EntityType.TOOL,
            "render_untrusted_image",
            source="gateway_runtime",
            attributes={
                "canonical_id": "mcp-tool:reference-lab:render-untrusted-image",
                "stable_id": "mcp-tool:reference-lab:render-untrusted-image",
            },
            index=4,
        )
    )
    runtime.add_node(
        _node(
            "identity:runtime:reference-workload",
            EntityType.SERVICE_ACCOUNT,
            "reference-evidence-workload",
            source="gateway_runtime",
            attributes={
                "canonical_id": "provider-identity:local:reference-evidence-workload",
                "provider_identity_id": "local:reference-evidence-workload",
            },
            index=4,
        )
    )
    runtime.add_edge(
        _edge(
            "tool:runtime:render-untrusted-image",
            "identity:runtime:reference-workload",
            RelationshipType.AUTHENTICATES_AS,
            scan_id=runtime.scan_id,
            source_kind="gateway_runtime",
            evidence_tier="runtime_observed",
            index=4,
            runtime_state="observed",
        )
    )

    identity = _graph("reference-identity-permission-scan", 5)
    identity.add_node(
        _node(
            "identity:model:reference-workload",
            EntityType.SERVICE_ACCOUNT,
            "reference-evidence-workload",
            source="identity_model",
            attributes={
                "canonical_id": "provider-identity:local:reference-evidence-workload",
                "provider_identity_id": "local:reference-evidence-workload",
                "modeled": True,
            },
            index=5,
        )
    )
    identity.add_node(
        _node(
            "data-store:reference-customer-records",
            EntityType.DATA_STORE,
            "Modeled customer records",
            source="identity_model",
            attributes={
                "canonical_id": "cloud-resource:local:object-store:customer-records",
                "cloud_resource_id": "local:object-store:customer-records",
                "data_sensitivity": "restricted",
                "data_classification_tier": "crown_jewel",
                "modeled": True,
            },
            index=5,
            severity="critical",
            risk_score=9.5,
        )
    )
    identity.add_edge(
        _edge(
            "identity:model:reference-workload",
            "data-store:reference-customer-records",
            RelationshipType.HAS_PERMISSION,
            scan_id=identity.scan_id,
            source_kind="identity_model",
            evidence_tier="modeled_infrastructure",
            index=5,
        )
    )
    return [repo, sbom, iac, mcp, runtime, identity]


async def _build_payload() -> dict[str, Any]:
    scanner_evidence = await _scanner_evidence()
    with tempfile.TemporaryDirectory(prefix="agent-bom-reference-evidence-") as temp_dir:
        store = SQLiteGraphStore(Path(temp_dir) / "graph.db")
        graphs = _snapshots()
        for graph in graphs:
            store.save_graph(graph)
        service = GraphCorrelationService(store, now=lambda: CREATED + timedelta(minutes=6))
        await service.start(tenants=[TENANT])
        try:
            await service.submit(
                CorrelationRequest(
                    correlation_id=CORRELATION_ID,
                    tenant_id=TENANT,
                    idempotency_key="reference-evidence-lab-v1",
                    name="Reference evidence lab",
                    scan_ids=tuple(graph.scan_id for graph in graphs),
                    max_age_hours=168,
                    allow_stale=False,
                )
            )
            completed = await service.wait(TENANT, CORRELATION_ID, timeout_seconds=10)
        finally:
            await service.stop()
        if completed.status.value != "complete":
            raise RuntimeError(f"reference correlation failed: {completed.failure_code}")
        output = store.load_graph(tenant_id=TENANT, scan_id=CORRELATION_ID)
        proof = next(
            (
                path
                for path in output.attack_paths
                if path.source == "service:reference-api" and path.target == "data-store:reference-customer-records"
            ),
            None,
        )
        if proof is None:
            raise RuntimeError("reference correlation did not produce the expected end-to-end attack path")

        return {
            "schema_version": "agent-bom.reference-evidence-lab/v1",
            "label": "Reference evidence lab — modeled local infrastructure",
            "generated_at": _timestamp(6),
            "container_digest": IMAGE_DIGEST,
            "scanner_evidence": scanner_evidence,
            "join_receipts": [
                {
                    "entity_type": "package",
                    "canonical_id": PURL,
                    "basis": "exact_purl",
                    "source_snapshots": ["reference-repository-scan", "reference-image-sbom-scan"],
                },
                {
                    "entity_type": "container",
                    "canonical_id": IMAGE_DIGEST,
                    "basis": "oci_digest",
                    "source_snapshots": ["reference-image-sbom-scan", "reference-kubernetes-iac-scan"],
                },
                {
                    "entity_type": "vulnerability",
                    "canonical_id": ADVISORY,
                    "basis": "canonical_advisory_id",
                    "source_snapshots": ["reference-image-sbom-scan", "reference-mcp-config-scan"],
                },
                {
                    "entity_type": "tool",
                    "canonical_id": "mcp-tool:reference-lab:render-untrusted-image",
                    "basis": "stable_runtime_id",
                    "source_snapshots": ["reference-mcp-config-scan", "reference-runtime-observation"],
                },
                {
                    "entity_type": "service_account",
                    "canonical_id": "provider-identity:local:reference-evidence-workload",
                    "basis": "provider_identity_id",
                    "source_snapshots": ["reference-runtime-observation", "reference-identity-permission-scan"],
                },
            ],
            "runtime_control": {
                "observed_event": "reference-observed-1",
                "strict_block": "verified",
                "blocked_event": "reference-blocked-1",
                "failure_mode": "deny",
                "global_default": "off",
            },
            "correlation": completed.to_dict(),
            "proof_path": proof.to_dict(),
            "output_counts": {
                "nodes": len(output.nodes),
                "edges": len(output.edges),
                "attack_paths": len(output.attack_paths),
            },
        }


def _render(payload: dict[str, Any]) -> str:
    material = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    payload_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
    payload["artifact_sha256"] = f"sha256:{payload_hash}"
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail when the committed generated proof is stale.")
    args = parser.parse_args()
    rendered = _render(asyncio.run(_build_payload()))
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"stale generated reference evidence: run {Path(__file__).relative_to(ROOT)}")
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
