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
      reachability: "confirmed",
      analysis: { status: "complete" },
      hops: nodes.map((node) => node.id),
      edges: ["contains", "contains", "vulnerable_to"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
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
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
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
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
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

  it("does not call an incomplete or non-traversable chain verified", () => {
    const path = {
      source: "service:api",
      target: "package:pillow",
      hops: ["service:api", "container:api", "package:pillow"],
      edges: ["contains", "contains"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["iac-scan"],
          evidence_tier: "modeled_infrastructure",
          confidence: 1,
          freshness: "stale_allowed",
          runtime_observed_state: "not_observed",
          direction: "directed",
          traversable: false,
          complete: true,
          truncated: false,
        },
      ],
    } as GraphAttackPath;

    render(<AttackPathCorrelationProof path={path} />);

    expect(screen.getByText("Path evidence incomplete")).toBeInTheDocument();
    expect(screen.getByText("Unavailable directed traversable hops evidenced")).toBeInTheDocument();
    expect(screen.getByText("Stale allowed")).toHaveClass("text-amber-700");
    expect(screen.queryByText("Path verified")).not.toBeInTheDocument();
  });

  it("does not call a fully traversable stale-allowed chain verified", () => {
    const path = {
      source: "service:api",
      target: "package:pillow",
      reachability: "likely",
      hops: ["service:api", "container:api", "package:pillow"],
      edges: ["contains", "contains"],
      hop_evidence: [
        {
          source_node_id: "service:api",
          target_node_id: "container:api",
          relationship: "contains",
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["iac-scan"],
          evidence_tier: "modeled_infrastructure",
          confidence: 1,
          freshness: "stale_allowed",
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
          relationship_provenance: "recorded",
          correlation_identity_status: "current",
          source_snapshot_ids: ["sbom-scan"],
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

    render(<AttackPathCorrelationProof path={path} />);

    expect(screen.getByText("Path evidence incomplete")).toBeInTheDocument();
    expect(screen.getByText("Stale allowed")).toBeInTheDocument();
    expect(screen.queryByText("Path verified")).not.toBeInTheDocument();
  });
});

it("discloses missing canonical path nodes instead of silently omitting anchors", () => {
  const path = {source: "a", target: "missing", hops: ["a", "missing"], edges: ["contains"]} as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} nodes={[{id: "a", label: "image", entity_type: "container"} as UnifiedNode]} />);
  expect(screen.getByText("1 path nodes unavailable")).toBeInTheDocument();
  expect(screen.getByText("image")).toBeInTheDocument();
  expect(screen.getByText("Path evidence incomplete")).toBeInTheDocument();
});

it("renders malformed legacy receipts without granting proof", () => {
  const path = {source: "a", target: "b", hops: ["a", "b"], edges: ["uses"], hop_evidence: [null, {source_snapshot_ids: null}]} as unknown as GraphAttackPath;
  render(<AttackPathCorrelationProof path={path} />);
  expect(screen.getByText("Path evidence incomplete")).toBeInTheDocument();
});
