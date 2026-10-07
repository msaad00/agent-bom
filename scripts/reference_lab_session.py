"""Optional real scan sessions for the credential-free reference lab."""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
from agent_bom.output import to_json
from agent_bom.parsers import scan_project_directory
from agent_bom.scanners.package_scan import default_scan_options, scan_agents


async def write_session(output: Path, proof: dict[str, Any], source_graphs: list[dict[str, Any]]) -> None:
    """Preserve inputs and normal scanner outputs; refuse to replace evidence."""
    if output.exists() and any(output.iterdir()):
        raise ValueError("Choose a new or empty session directory; existing evidence is preserved")
    output.mkdir(parents=True, exist_ok=True)
    tenant = proof["correlation"]["tenant_id"]
    scans = []
    findings = {}
    for phase, version in (("before", "9.0.0"), ("after", "10.0.1")):
        manifest = f"Pillow=={version}\n"
        (output / f"{phase}-input.txt").write_text(manifest)
        with tempfile.TemporaryDirectory(prefix="agent-bom-reference-rescan-") as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(manifest)
            parsed = scan_project_directory(root, max_depth=1)
            packages = [package for path in sorted(parsed, key=str) for package in parsed[path]]
            agents = [
                Agent(
                    name="Reference lab repository",
                    agent_type=AgentType.CUSTOM,
                    config_path="reference-lab-repository",
                    source="repo-lockfiles",
                    metadata={"evidence_origin": "local-reference-lab", "owner": "example-platform-team"},
                    mcp_servers=[MCPServer(name="repository-dependencies", command="", packages=packages)],
                )
            ]
            blast_radii = await scan_agents(
                agents, show_scan_banner=False, options=default_scan_options(offline=True, demo_advisories=True, project_dir=str(root))
            )
        observed = datetime.now(timezone.utc)
        scan_id = f"reference-rescan-{phase}"
        result = to_json(
            AIBOMReport(agents=agents, blast_radii=blast_radii, scan_id=scan_id, generated_at=observed, scan_sources=["repo-lockfiles"])
        )
        graph = build_unified_graph_from_report(result, scan_id=scan_id, tenant_id=tenant)
        graph.created_at = observed.isoformat()
        source_graphs.append(graph.to_dict())
        findings[phase] = sorted({v.id for p in packages for v in p.vulnerabilities})
        scans.append(
            {
                "scan_id": scan_id,
                "source_id": "reference-lab-repository",
                "phase": phase,
                "input_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
                "completed_at": observed.isoformat(),
                "result": result,
            }
        )
    advisory = proof["scanner_evidence"]["advisory"]
    if advisory not in findings["before"] or advisory in findings["after"]:
        raise RuntimeError("Reference rescan did not remove the pinned advisory after the changed input")
    session = {
        "schema_version": "agent-bom.reference-lab-session/v1",
        "tenant_id": tenant,
        "label": proof["label"],
        "correlated_graph": proof["capture_fixture"]["graph"],
        "source_graphs": source_graphs,
        "scans": scans,
        "evidence_matrix": proof["evidence_matrix"],
        "remediation_verification": {
            "advisory": advisory,
            "before": findings["before"],
            "after": findings["after"],
            "status": "pinned_advisory_absent_after_input_change",
            "owner": "example-platform-team",
            "remaining_gaps": [
                "No dependency installed or deployment changed",
                "No live provider collection",
                "No resource activity observed",
                "Offline pinned advisory coverage only",
            ],
        },
    }
    (output / "local-session.json").write_text(json.dumps(session, indent=2) + "\n")
