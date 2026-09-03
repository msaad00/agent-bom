#!/usr/bin/env python3
"""Generate the credential-free correlated evidence reference lab proof."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.api.graph_store import SQLiteGraphStore  # noqa: E402
from agent_bom.discovery import parse_mcp_config  # noqa: E402
from agent_bom.gateway_server import GatewaySettings, create_gateway_app  # noqa: E402
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry  # noqa: E402
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode  # noqa: E402
from agent_bom.graph.correlation_service import CorrelationRequest, GraphCorrelationService  # noqa: E402
from agent_bom.graph.correlation_receipts import correlation_run_receipt_payload  # noqa: E402
from agent_bom.iac import scan_iac_with_context  # noqa: E402
from agent_bom.parsers import scan_project_directory  # noqa: E402
from agent_bom.runtime.correlation_facts import create_runtime_facts_bundle_from_correlation  # noqa: E402
from agent_bom.sbom import load_sbom  # noqa: E402
from agent_bom.scanners.package_scan import default_scan_options, scan_packages  # noqa: E402

LAB = ROOT / "examples" / "reference-evidence-lab"
OUTPUT = LAB / "generated" / "correlation-proof.json"
OUTPUT_DIGEST = LAB / "generated" / "correlation-proof.sha256"
PINNED_PACKAGE_INPUT = LAB / "pinned-package.txt"
SBOM_INPUT = LAB / "sbom.cdx.json"
KUBERNETES_INPUT = LAB / "deployment.yaml"
MCP_INPUT = LAB / "mcp.json"
IDENTITY_INPUT = LAB / "identity-model.json"
TENANT = "reference-lab"
CORRELATION_ID = "reference-evidence-correlation-v1"
CREATED = datetime(2026, 8, 30, 4, 0, tzinfo=timezone.utc)
IMAGE_DIGEST = "sha256:7d3e21c47d244111d7502503e9868ce01f2dfd77f0d71d876a3a8da1f477d58a"
PURL = "pkg:pypi/pillow@9.0.0"
ADVISORY = "CVE-2023-4863"
RUNTIME_ID = "reference-evidence-workload"
TOOL_ID = "mcp-tool:reference-lab:render-untrusted-image"
TOOL_NAME = "render_untrusted_image"
_RUNTIME_FACTS_KEY = b"reference-lab-runtime-facts-key-32-bytes"


def _timestamp(index: int) -> str:
    return (CREATED + timedelta(minutes=index)).isoformat()


def _artifact_receipt(path: Path, parser: str) -> dict[str, str]:
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
        "parser": parser,
    }


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
    # Materialize the intentionally vulnerable fixture only inside an isolated
    # scanner workspace. Keeping it out of a repository requirements.txt makes
    # clear that Pillow 9.0.0 is evidence input, not an installable dependency.
    with tempfile.TemporaryDirectory(prefix="agent-bom-reference-scanner-") as temp_dir:
        scanner_root = Path(temp_dir)
        (scanner_root / "requirements.txt").write_text(PINNED_PACKAGE_INPUT.read_text(encoding="utf-8"), encoding="utf-8")
        discovered = scan_project_directory(scanner_root, max_depth=1)
        packages = [package for directory in sorted(discovered, key=str) for package in discovered[directory]]
        pillow = next(
            (package for package in packages if package.name.lower() == "pillow" and package.version == "9.0.0"),
            None,
        )
        if pillow is None:
            raise RuntimeError("reference lab parser did not discover Pillow 9.0.0")
        await scan_packages(
            packages,
            options=default_scan_options(
                offline=True,
                demo_advisories=True,
                project_dir=str(scanner_root),
            ),
        )
    vulnerability = next((item for item in pillow.vulnerabilities if item.id == ADVISORY), None)
    if vulnerability is None:
        raise RuntimeError("reference lab scanner did not match the pinned CVE-2023-4863 advisory")
    return {
        "parser": "agent_bom.parsers.scan_project_directory",
        "scanner": "agent_bom.scanners.package_scan.scan_packages",
        "mode": "offline_bundled_pinned_advisory",
        "evidence_input": "examples/reference-evidence-lab/pinned-package.txt",
        "scanner_manifest": "isolated temporary requirements.txt",
        "package": PURL,
        "advisory": vulnerability.id,
        "severity": vulnerability.severity.value,
        "cvss_score": vulnerability.cvss_score,
        "is_kev": vulnerability.is_kev,
    }


def _source_evidence() -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    sbom_packages, sbom_format, sbom_name = load_sbom(str(SBOM_INPUT))
    sbom_package = next((package for package in sbom_packages if package.purl == PURL), None)
    if sbom_format != "cyclonedx" or sbom_package is None:
        raise RuntimeError("reference lab SBOM parser did not discover the exact Pillow PURL")
    sbom_document = json.loads(SBOM_INPUT.read_text(encoding="utf-8"))
    sbom_component = sbom_document.get("metadata", {}).get("component", {})
    image_digest = str(sbom_component.get("version") or "")
    if image_digest != IMAGE_DIGEST or sbom_name != "reference-evidence-api":
        raise RuntimeError("reference lab SBOM container identity does not match the pinned digest")

    iac_result = scan_iac_with_context(KUBERNETES_INPUT)
    kubernetes_verdict = next((verdict for verdict in iac_result.verdicts if verdict.scanner_id == "kubernetes"), None)
    if kubernetes_verdict is None or kubernetes_verdict.status != "ran":
        raise RuntimeError("reference lab Kubernetes scanner did not execute")
    resources = [item for item in yaml.safe_load_all(KUBERNETES_INPUT.read_text(encoding="utf-8")) if isinstance(item, dict)]
    service = next((item for item in resources if item.get("kind") == "Service"), None)
    deployment = next((item for item in resources if item.get("kind") == "Deployment"), None)
    if service is None or deployment is None:
        raise RuntimeError("reference lab Kubernetes input must contain one Service and one Deployment")
    container = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0]
    image = str(container.get("image") or "")
    if "@" not in image or image.rsplit("@", 1)[-1] != image_digest:
        raise RuntimeError("reference lab Kubernetes image must bind the SBOM digest")

    mcp_document = json.loads(MCP_INPUT.read_text(encoding="utf-8"))
    mcp_servers = parse_mcp_config(mcp_document, str(MCP_INPUT.relative_to(ROOT)))
    server = next((item for item in mcp_servers if item.name == "document-review" and not item.security_blocked), None)
    raw_server = mcp_document.get("mcpServers", {}).get("document-review", {})
    raw_tool = next((item for item in raw_server.get("tools", []) if item.get("name") == TOOL_NAME), None)
    if server is None or raw_tool is None or raw_tool.get("stable_id") != TOOL_ID:
        raise RuntimeError("reference lab MCP parser did not bind the expected server and tool")

    identity = json.loads(IDENTITY_INPUT.read_text(encoding="utf-8"))
    identity_record = identity.get("workload_identity", {})
    permissions = identity.get("permissions")
    if (
        identity.get("schema_version") != "agent-bom.reference-identity-model/v1"
        or identity_record.get("runtime_id") != RUNTIME_ID
        or not isinstance(permissions, list)
        or len(permissions) != 1
    ):
        raise RuntimeError("reference lab identity model is invalid")
    permission = permissions[0]
    if permission.get("relationship") != RelationshipType.HAS_PERMISSION.value or not isinstance(permission.get("target"), dict):
        raise RuntimeError("reference lab identity model must contain one bounded permission")

    receipts = {
        "dependency": _artifact_receipt(PINNED_PACKAGE_INPUT, "agent_bom.parsers.scan_project_directory"),
        "sbom": _artifact_receipt(SBOM_INPUT, "agent_bom.sbom.load_sbom"),
        "kubernetes": _artifact_receipt(KUBERNETES_INPUT, "agent_bom.iac.scan_iac_with_context + yaml.safe_load_all"),
        "mcp": _artifact_receipt(MCP_INPUT, "agent_bom.discovery.parse_mcp_config"),
        "identity": _artifact_receipt(IDENTITY_INPUT, "strict local identity model parser"),
    }
    return receipts, {
        "sbom": {"package": sbom_package, "image_digest": image_digest},
        "kubernetes": {
            "service_name": str(service.get("metadata", {}).get("name") or ""),
            "service_uid": str(service.get("metadata", {}).get("uid") or ""),
            "internet_exposed": service.get("spec", {}).get("type") == "LoadBalancer",
            "workload_name": str(deployment.get("metadata", {}).get("name") or ""),
            "workload_uid": str(deployment.get("metadata", {}).get("uid") or ""),
            "service_account": str(deployment.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName") or ""),
            "image_digest": image_digest,
        },
        "mcp": {"server": server, "tool_name": str(raw_tool["name"]), "tool_id": str(raw_tool["stable_id"])},
        "identity": {"identity": identity_record, "permission": permission},
    }


def _gateway_call() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": "reference-lab-call",
        "method": "tools/call",
        "params": {"name": TOOL_NAME, "arguments": {}, "_meta": {"agent_identity": "reference-token"}},
    }


def _gateway_settings(*, mode: str, caller: Any, audit_sink: Any = None) -> GatewaySettings:
    return GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="reference", url="http://reference.invalid/mcp")]),
        policy={"agent_tokens": {"reference-token": RUNTIME_ID}},
        upstream_caller=caller,
        audit_sink=audit_sink,
        bearer_token="reference-gateway-token",
        graph_reachability_enforcement_mode=mode,
        graph_reachability_failure_mode="deny",
    )


def _runtime_observation() -> dict[str, str]:
    calls: list[str] = []

    async def caller(_upstream: Any, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        calls.append(str(message.get("params", {}).get("name") or ""))
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def sink(_event: dict[str, Any]) -> None:
        return None

    with patch.dict(
        os.environ,
        {"AGENT_BOM_EPHEMERAL_STORE": "1", "AGENT_BOM_TENANT_ID": TENANT},
        clear=False,
    ):
        with TestClient(create_gateway_app(_gateway_settings(mode="off", caller=caller, audit_sink=sink))) as client:
            response = client.post(
                "/mcp/reference",
                headers={"Authorization": "Bearer reference-gateway-token"},
                json=_gateway_call(),
            )
    if response.status_code != 200 or response.json().get("result") != {"ok": True} or calls != [TOOL_NAME]:
        raise RuntimeError("reference lab gateway observation smoke failed")
    return {
        "observed_event": "live-jsonrpc-allow",
        "allow_result": "upstream_called",
        "runtime_id": RUNTIME_ID,
        "tool_id": TOOL_ID,
    }


def _runtime_control(run: Any, graph: UnifiedGraph, snapshot_metadata: dict[str, Any], observation: dict[str, str]) -> dict[str, Any]:
    fixed_now = CREATED + timedelta(minutes=6)

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return fixed_now if tz is None else fixed_now.astimezone(tz)

    audit: list[dict[str, Any]] = []
    upstream_calls: list[str] = []

    async def caller(_upstream: Any, message: dict[str, Any], _headers: dict[str, str]) -> dict[str, Any]:
        upstream_calls.append(str(message.get("params", {}).get("name") or ""))
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def sink(event: dict[str, Any]) -> None:
        audit.append(event)

    with patch("agent_bom.runtime.correlation_facts.datetime", FixedClock):
        bundle = create_runtime_facts_bundle_from_correlation(
            run,
            graph,
            snapshot_metadata=snapshot_metadata,
            signing_key=_RUNTIME_FACTS_KEY,
            ttl_seconds=300,
            now=fixed_now,
            key_id="reference-lab",
        )

        async def fetch() -> dict[str, Any]:
            return bundle

        settings = _gateway_settings(mode="enforce", caller=caller, audit_sink=sink)
        settings.graph_reachability_bundle_fetcher = fetch
        settings.graph_reachability_bundle_signing_key = _RUNTIME_FACTS_KEY
        settings.graph_reachability_bundle_tenant_id = TENANT
        settings.graph_reachability_bundle_poll_interval_seconds = 0
        with patch.dict(
            os.environ,
            {"AGENT_BOM_EPHEMERAL_STORE": "1", "AGENT_BOM_TENANT_ID": TENANT},
            clear=False,
        ):
            with TestClient(create_gateway_app(settings)) as client:
                response = client.post(
                    "/mcp/reference",
                    headers={"Authorization": "Bearer reference-gateway-token"},
                    json=_gateway_call(),
                )

    body = response.json()
    error = body.get("error") if isinstance(body, dict) else None
    blocked = next((event for event in audit if event.get("action") == "gateway.graph_reachability_blocked"), None)
    if response.status_code != 200 or not isinstance(error, dict) or error.get("code") != -32001 or upstream_calls or blocked is None:
        raise RuntimeError("reference lab strict gateway smoke failed")
    data = error.get("data") if isinstance(error.get("data"), dict) else {}
    return {
        **observation,
        "verification": "live_jsonrpc_gateway_smoke",
        "strict_block": "verified",
        "blocked_event": str(blocked.get("event_id") or blocked.get("action") or "gateway.graph_reachability_blocked"),
        "blocked_error_code": int(error["code"]),
        "policy_id": "strict-correlated-evidence",
        "policy_source": str(data.get("policy_source") or ""),
        "correlation_id": str(blocked.get("correlation_id") or ""),
        "manifest_sha256": str(blocked.get("manifest_sha256") or ""),
        "failure_mode": "deny",
        "global_default": "off",
    }


def _snapshots(
    scanner_evidence: dict[str, Any],
    sources: dict[str, Any],
    runtime_observation: dict[str, str],
) -> list[UnifiedGraph]:
    purl = str(scanner_evidence["package"])
    advisory = str(scanner_evidence["advisory"])
    image_digest = str(sources["sbom"]["image_digest"])
    kubernetes = sources["kubernetes"]
    mcp_evidence = sources["mcp"]
    identity_evidence = sources["identity"]
    identity = identity_evidence["identity"]
    permission = identity_evidence["permission"]
    target = permission["target"]
    repo = _graph("reference-repository-scan", 0)
    repo.add_node(
        _node(
            "source:pinned-package",
            EntityType.SOURCE_FILE,
            "pinned-package.txt",
            source="repository_parser",
            attributes={
                "repository_path": "examples/reference-evidence-lab/pinned-package.txt",
                "content_sha256": _artifact_receipt(PINNED_PACKAGE_INPUT, "")["sha256"],
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
            attributes={"purl": purl, "canonical_id": purl},
            index=0,
        )
    )
    repo.add_edge(
        _edge(
            "source:pinned-package",
            "package:repo:pillow",
            RelationshipType.DEPENDS_ON,
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
            f"reference-evidence-api@{image_digest}",
            source="cyclonedx_sbom",
            attributes={"image_digest": image_digest, "sbom": str(SBOM_INPUT.relative_to(ROOT))},
            index=1,
        )
    )
    sbom.add_node(
        _node(
            "package:sbom:pillow",
            EntityType.PACKAGE,
            "pillow@9.0.0",
            source="cyclonedx_sbom",
            attributes={"purl": purl, "canonical_id": purl},
            index=1,
            severity="high",
            risk_score=8.8,
        )
    )
    sbom.add_node(
        _node(
            "vulnerability:sbom:cve-2023-4863",
            EntityType.VULNERABILITY,
            advisory,
            source="bundled_advisory_scanner",
            attributes={
                "canonical_id": advisory,
                "finding_id": "reference-finding-cve-2023-4863",
                "is_kev": bool(scanner_evidence["is_kev"]),
            },
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
            f"Public {kubernetes['service_name']} service",
            source="kubernetes_iac",
            attributes={
                "canonical_id": f"kubernetes-uid:{kubernetes['service_uid']}",
                "internet_exposed": bool(kubernetes["internet_exposed"]),
                "modeled": True,
            },
            index=2,
            severity="high",
            risk_score=8.0,
        )
    )
    iac.add_node(
        _node(
            "workload:reference-api",
            EntityType.AGENT,
            f"{kubernetes['workload_name']} workload",
            source="kubernetes_iac",
            attributes={
                "canonical_id": f"kubernetes-uid:{kubernetes['workload_uid']}",
                "runtime_id": str(identity["runtime_id"]),
                "service_account": str(kubernetes["service_account"]),
                "modeled": True,
            },
            index=2,
        )
    )
    iac.add_node(
        _node(
            "container:iac:reference-api",
            EntityType.CONTAINER,
            f"reference-evidence-api@{image_digest}",
            source="kubernetes_iac",
            attributes={"image_digest": image_digest, "modeled": True},
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
            advisory,
            source="mcp_config",
            attributes={"canonical_id": advisory},
            index=3,
            severity="high",
            risk_score=8.8,
        )
    )
    mcp.add_node(
        _node(
            "tool:mcp:render-untrusted-image",
            EntityType.TOOL,
            str(mcp_evidence["tool_name"]),
            source="mcp_config",
            attributes={
                "canonical_id": str(mcp_evidence["tool_id"]),
                "stable_id": str(mcp_evidence["tool_id"]),
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
            str(mcp_evidence["tool_name"]),
            source="gateway_runtime",
            attributes={
                "canonical_id": str(runtime_observation["tool_id"]),
                "stable_id": str(runtime_observation["tool_id"]),
                "observation": str(runtime_observation["observed_event"]),
            },
            index=4,
        )
    )
    runtime.add_node(
        _node(
            "identity:runtime:reference-workload",
            EntityType.SERVICE_ACCOUNT,
            str(identity["runtime_id"]),
            source="gateway_runtime",
            attributes={
                "canonical_id": f"provider-identity:{identity['provider_identity_id']}",
                "provider_identity_id": str(identity["provider_identity_id"]),
                "runtime_id": str(runtime_observation["runtime_id"]),
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

    identity_graph = _graph("reference-identity-permission-scan", 5)
    identity_graph.add_node(
        _node(
            "identity:model:reference-workload",
            EntityType.SERVICE_ACCOUNT,
            str(identity["runtime_id"]),
            source="identity_model",
            attributes={
                "canonical_id": f"provider-identity:{identity['provider_identity_id']}",
                "provider_identity_id": str(identity["provider_identity_id"]),
                "modeled": True,
            },
            index=5,
        )
    )
    identity_graph.add_node(
        _node(
            "data-store:reference-customer-records",
            EntityType.DATA_STORE,
            str(target["label"]),
            source="identity_model",
            attributes={
                "canonical_id": f"cloud-resource:{target['resource_id']}",
                "cloud_resource_id": str(target["resource_id"]),
                "data_sensitivity": str(target["data_sensitivity"]),
                "data_classification_tier": str(target["data_classification_tier"]),
                "modeled": True,
            },
            index=5,
            severity="critical",
            risk_score=9.5,
        )
    )
    identity_graph.add_edge(
        _edge(
            "identity:model:reference-workload",
            "data-store:reference-customer-records",
            RelationshipType.HAS_PERMISSION,
            scan_id=identity_graph.scan_id,
            source_kind="identity_model",
            evidence_tier="modeled_infrastructure",
            index=5,
        )
    )
    return [repo, sbom, iac, mcp, runtime, identity_graph]


async def _build_payload() -> dict[str, Any]:
    scanner_evidence = await _scanner_evidence()
    source_artifacts, sources = _source_evidence()
    runtime_observation = _runtime_observation()
    with tempfile.TemporaryDirectory(prefix="agent-bom-reference-evidence-") as temp_dir:
        store = SQLiteGraphStore(Path(temp_dir) / "graph.db")
        graphs = _snapshots(scanner_evidence, sources, runtime_observation)
        for graph in graphs:
            store.save_graph(graph)
        service = GraphCorrelationService(
            store,
            now=lambda: CREATED + timedelta(minutes=6),
            receipt_signing_key=_RUNTIME_FACTS_KEY,
            receipt_signing_key_id="reference-lab-v1",
        )
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
        snapshot_metadata = next(row for row in store.list_snapshots(tenant_id=TENANT, limit=32) if row["scan_id"] == CORRELATION_ID)
        runtime_control = _runtime_control(completed, output, snapshot_metadata, runtime_observation)

        purl = str(scanner_evidence["package"])
        advisory = str(scanner_evidence["advisory"])
        image_digest = str(sources["sbom"]["image_digest"])
        tool_id = str(sources["mcp"]["tool_id"])
        provider_identity_id = str(sources["identity"]["identity"]["provider_identity_id"])

        return {
            "schema_version": "agent-bom.reference-evidence-lab/v1",
            "label": "Reference evidence lab — modeled local infrastructure",
            "generated_at": _timestamp(6),
            "container_digest": image_digest,
            "scanner_evidence": scanner_evidence,
            "source_artifacts": source_artifacts,
            "join_receipts": [
                {
                    "entity_type": "package",
                    "canonical_id": purl,
                    "basis": "exact_purl",
                    "source_snapshots": ["reference-repository-scan", "reference-image-sbom-scan"],
                },
                {
                    "entity_type": "container",
                    "canonical_id": image_digest,
                    "basis": "oci_digest",
                    "source_snapshots": ["reference-image-sbom-scan", "reference-kubernetes-iac-scan"],
                },
                {
                    "entity_type": "vulnerability",
                    "canonical_id": advisory,
                    "basis": "canonical_advisory_id",
                    "source_snapshots": ["reference-image-sbom-scan", "reference-mcp-config-scan"],
                },
                {
                    "entity_type": "tool",
                    "canonical_id": tool_id,
                    "basis": "stable_runtime_id",
                    "source_snapshots": ["reference-mcp-config-scan", "reference-runtime-observation"],
                },
                {
                    "entity_type": "service_account",
                    "canonical_id": f"provider-identity:{provider_identity_id}",
                    "basis": "provider_identity_id",
                    "source_snapshots": ["reference-runtime-observation", "reference-identity-permission-scan"],
                },
            ],
            "runtime_control": runtime_control,
            "correlation": correlation_run_receipt_payload(completed.to_dict(), signing_key=_RUNTIME_FACTS_KEY),
            "proof_path": proof.to_dict(),
            "capture_fixture": {
                "graph": output.to_dict(),
                "snapshots": [
                    {
                        "scan_id": graph.scan_id,
                        "created_at": graph.created_at,
                        "node_count": len(graph.nodes),
                        "edge_count": len(graph.edges),
                        "risk_summary": graph.stats()["severity_counts"],
                        "snapshot_kind": "scan",
                    }
                    for graph in graphs
                ],
            },
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
    rendered_digest = f"sha256:{hashlib.sha256(rendered.encode('utf-8')).hexdigest()}\n"
    if args.check:
        if (
            not OUTPUT.exists()
            or OUTPUT.read_text(encoding="utf-8") != rendered
            or not OUTPUT_DIGEST.exists()
            or OUTPUT_DIGEST.read_text(encoding="utf-8") != rendered_digest
        ):
            print(f"stale generated reference evidence: run {Path(__file__).relative_to(ROOT)}")
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    OUTPUT_DIGEST.write_text(rendered_digest, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
