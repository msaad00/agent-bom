import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AttackPathCorrelationProof } from "@/components/attack-path-correlation-proof";
import type { GraphAttackPath } from "@/lib/api-types";
import type { UnifiedNode } from "@/lib/graph-schema";

describe("AttackPathCorrelationProof", () => {
  it("summarizes verified proof and keeps exact per-hop receipts inspectable", () => {
    const digest = "sha256:7d3e21c47d244111d7502503e9868ce01f2dfd77f0d71d876a3a8da1f477d58a";
    const nodes = [
      { id: "service:api", entity_type: "server", label: "Public API" },
      { id: "container:api", entity_type: "container", label: `reference-api@${digest}` },
      { id: "package:pillow", entity_type: "package", label: "pillow@9.0.0" },
      { id: "vulnerability:webp", entity_type: "vulnerability", label: "CVE-2023-4863" },
    ] as UnifiedNode[];
    const path = {
      source: "service:api",
      target: "vulnerability:webp",
      hops: nodes.map((node) => node.id),
      edges: ["contains", "contains", "vulnerable_to"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          source_snapshot_ids: ["reference-kubernetes-iac-scan"],
          evidence_tier: "modeled_infrastructure",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
        {
          source_node_id: "container:api",
          target_node_id: "package:pillow",
          relationship: "contains",
          source_snapshot_ids: ["reference-image-sbom-scan"],
          evidence_tier: "static_evidence",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
        {
          source_node_id: "package:pillow",
          target_node_id: "vulnerability:webp",
          relationship: "vulnerable_to",
          source_snapshot_ids: ["reference-image-sbom-scan"],
          evidence_tier: "static_evidence",
          confidence: 1,
          freshness: "fresh",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: true,
          complete: true,
          truncated: false,
        },
      ],
    } as GraphAttackPath;

    render(<AttackPathCorrelationProof path={path} nodes={nodes} />);

    expect(screen.getByText("Path verified")).toBeInTheDocument();
    expect(screen.getByText("3/3 directed traversable hops evidenced")).toBeInTheDocument();
    expect(screen.getByText(`reference-api@${digest}`)).toBeInTheDocument();
    expect(screen.getByText("pillow@9.0.0")).toBeInTheDocument();
    expect(screen.getByText("CVE-2023-4863")).toBeInTheDocument();
    expect(screen.queryByText("reference-kubernetes-iac-scan")).not.toBeVisible();
    expect(screen.getByText("Inspect 3 hop receipts")).toBeInTheDocument();

    screen.getByText("Inspect 3 hop receipts").click();
    expect(screen.getByText("reference-kubernetes-iac-scan")).toBeInTheDocument();
    expect(screen.getAllByText("reference-image-sbom-scan")).toHaveLength(2);
    expect(screen.getByText("3. vulnerable_to")).toBeInTheDocument();
  });
});
