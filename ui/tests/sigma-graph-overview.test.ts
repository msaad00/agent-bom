import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import type { UnifiedGraphData, UnifiedNode, UnifiedEdge } from "@/lib/graph-schema";
import { EntityType, NodeStatus, RelationshipType } from "@/lib/graph-schema";
import {
  buildSigmaGraphOverviewModel,
  buildSigmaGraphOverviewModelFromUnifiedGraph,
} from "@/lib/sigma-graph-overview";

function node(id: string, data: Partial<LineageNodeData> = {}): Node<LineageNodeData> {
  return {
    id,
    position: { x: data.nodeType === "agent" ? 0 : 100, y: data.nodeType === "agent" ? 0 : 80 },
    data: {
      label: id,
      nodeType: "package",
      ...data,
    },
  };
}

function edge(id: string, source: string, target: string, relationship = "depends_on"): Edge {
  return {
    id,
    source,
    target,
    data: { relationship },
    style: { strokeWidth: 2 },
  };
}

function unifiedNode(
  id: string,
  entityType: EntityType,
  overrides: Partial<UnifiedNode> = {},
): UnifiedNode {
  return {
    id,
    entity_type: entityType,
    label: id,
    category_uid: 5,
    class_uid: 4001,
    type_uid: 0,
    status: NodeStatus.ACTIVE,
    risk_score: 0,
    severity: "unknown",
    severity_id: 0,
    first_seen: "2026-05-14T00:00:00Z",
    last_seen: "2026-05-14T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    data_sources: ["fixture"],
    dimensions: {},
    ...overrides,
  };
}

function unifiedEdge(
  id: string,
  source: string,
  target: string,
  relationship: RelationshipType,
  overrides: Partial<UnifiedEdge> = {},
): UnifiedEdge {
  return {
    id,
    source,
    target,
    relationship,
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: "2026-05-14T00:00:00Z",
    last_seen: "2026-05-14T00:00:00Z",
    evidence: {},
    activity_id: 0,
    ...overrides,
  };
}

function unifiedGraph(
  nodes: UnifiedNode[],
  edges: UnifiedEdge[],
): UnifiedGraphData {
  return {
    scan_id: "scan-fixture",
    tenant_id: "tenant-fixture",
    created_at: "2026-05-14T00:00:00Z",
    nodes,
    edges,
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
    },
  };
}

describe("sigma graph overview", () => {
  it("adapts lineage graph data into a graphology model for Sigma", () => {
    const model = buildSigmaGraphOverviewModel(
      [
        node("agent-a", { nodeType: "agent", label: "analyst-agent" }),
        node("pkg-a", { nodeType: "package", label: "requests", riskScore: 82 }),
        node("cve-a", {
          nodeType: "vulnerability",
          label: "CVE-2026-0001",
          severity: "critical",
          highlighted: true,
        }),
      ],
      [
        edge("agent-pkg", "agent-a", "pkg-a", "uses"),
        edge("pkg-cve", "pkg-a", "cve-a", "vulnerable_to"),
        edge("missing", "pkg-a", "does-not-exist", "depends_on"),
      ],
    );

    expect(model.graph.order).toBe(3);
    expect(model.graph.size).toBe(2);
    // Labels are decluttered for readability at scale: only genuinely
    // highlighted nodes force their label. A plain agent no longer force-draws
    // its label (force-labeling every agent/server/cred/tool smeared hundreds
    // of labels together on a broad estate); the highlighted CVE still does.
    expect(model.graph.getNodeAttribute("agent-a", "forceLabel")).toBe(false);
    expect(model.graph.getNodeAttribute("cve-a", "forceLabel")).toBe(true);
    expect(model.graph.getNodeAttribute("cve-a", "highlighted")).toBe(true);
    expect(model.graph.getNodeAttribute("cve-a", "size")).toBeGreaterThan(
      model.graph.getNodeAttribute("pkg-a", "size"),
    );
    expect(model.graph.getEdgeAttribute("pkg-cve", "relationship")).toBe("vulnerable_to");
    expect(model.graph.hasEdge("missing")).toBe(false);
    expect(model.summary.criticalFindings).toBe(1);
  });

  it("preserves dimmed state and edge highlighting for focused overview data", () => {
    const model = buildSigmaGraphOverviewModel(
      [
        node("agent-a", { nodeType: "agent", highlighted: true }),
        node("pkg-a", { nodeType: "package" }),
        node("pkg-b", { nodeType: "package", dimmed: true }),
      ],
      [edge("focused", "agent-a", "pkg-a", "uses"), edge("dimmed", "pkg-a", "pkg-b", "depends_on")],
    );

    expect(model.graph.getNodeAttribute("pkg-b", "hidden")).toBe(true);
    expect(model.graph.getEdgeAttribute("focused", "highlighted")).toBe(true);
    expect(model.graph.getEdgeAttribute("dimmed", "hidden")).toBe(true);
  });

  it("adapts canonical unified graph data before building the Sigma model", () => {
    const model = buildSigmaGraphOverviewModelFromUnifiedGraph(
      unifiedGraph(
        [
          unifiedNode("agent-a", EntityType.AGENT, { label: "agent-a" }),
          unifiedNode("server-a", EntityType.SERVER, { label: "mcp-server" }),
          unifiedNode("pkg-a", EntityType.PACKAGE, { label: "requests", risk_score: 41 }),
          unifiedNode("cve-a", EntityType.VULNERABILITY, {
            label: "CVE-2026-0001",
            risk_score: 95,
            severity: "critical",
            severity_id: 5,
          }),
        ],
        [
          unifiedEdge("agent-server", "agent-a", "server-a", RelationshipType.USES),
          unifiedEdge("server-pkg", "server-a", "pkg-a", RelationshipType.DEPENDS_ON),
          unifiedEdge("pkg-cve", "pkg-a", "cve-a", RelationshipType.VULNERABLE_TO, {
            weight: 3,
          }),
          unifiedEdge("dangling", "pkg-a", "missing-node", RelationshipType.DEPENDS_ON),
        ],
      ),
    );

    expect(model.graph.order).toBe(4);
    expect(model.graph.size).toBe(3);
    expect(model.graph.getNodeAttribute("agent-a", "nodeType")).toBe("agent");
    expect(model.graph.getNodeAttribute("cve-a", "severity")).toBe("critical");
    expect(model.graph.getEdgeAttribute("pkg-cve", "relationship")).toBe("vulnerable_to");
    expect(model.graph.hasEdge("dangling")).toBe(false);
    expect(model.summary.criticalFindings).toBe(1);
  });
});

describe("environment map groups", () => {
  it("keeps account boundaries and unknown metadata without inventing graph entities", () => {
    const nodes = [
      node("a", { dimensions: { cloud_provider: "aws", environment: "prod" }, attributes: { account_id: "one" } }),
      node("b", { dimensions: { cloud_provider: "aws", environment: "prod" }, attributes: { account_id: "two" } }),
      node("c", { dataSources: ["production-import"] }),
    ];
    const edges = [edge("cross", "a", "b")];
    const model = buildSigmaGraphOverviewModel(nodes, edges, "environment");
    expect(model.groups.map((group) => group.label)).toContain("aws / one / prod");
    expect(model.groups.map((group) => group.label)).toContain("aws / two / prod");
    expect(model.groups.map((group) => group.label)).toContain("Provider unknown / Account unknown / Environment unknown");
    expect(model.graph.order).toBe(3);
    expect(model.graph.size).toBe(1);
    expect(model.graph.source("cross")).toBe("a");
    expect(model.graph.target("cross")).toBe("b");
    expect(new Set(model.overview.nodes.map((item) => `${item.x}:${item.y}`)).size).toBe(3);
    expect(buildSigmaGraphOverviewModel(nodes, edges, "environment").groups).toEqual(model.groups);
  });
});

it.each(["type", "environment"] as const)("packs %s clusters organically, with stable positions and separated bounds", grouping => {
  const types = ["agent", "package", "vulnerability"] as const;
  const nodes = types.flatMap((type, group) => Array.from({ length: [1, 120, 35][group]! }, (_, index) => node(`${type}-${index.toString().padStart(3, "0")}`, {
    nodeType: type, severity: "critical", dimensions: { cloud_provider: "aws", environment: `scope-${group}` },
  })));
  const links = [edge("recorded", "agent-000", "package-000", "uses")];
  const model = buildSigmaGraphOverviewModel(nodes, links, grouping);
  const reordered = buildSigmaGraphOverviewModel([...nodes].reverse(), links, grouping);
  for (const node of model.overview.nodes) {
    expect(reordered.graph.getNodeAttribute(node.id, "x")).toBe(node.x);
    expect(reordered.graph.getNodeAttribute(node.id, "y")).toBe(node.y);
  }
  const disks = types.map(type => {
    const members = model.overview.nodes.filter(node => node.nodeType === type);
    const center = model.graph.getNodeAttributes(`${type}-000`);
    const radius = Math.max(...members.map(node => Math.hypot(node.x - center.x, node.y - center.y) + node.size));
    return { x: center.x, y: center.y, radius };
  });
  for (let a = 0; a < disks.length; a++) for (let b = a + 1; b < disks.length; b++) {
    expect(Math.hypot(disks[a]!.x - disks[b]!.x, disks[a]!.y - disks[b]!.y)).toBeGreaterThan(disks[a]!.radius + disks[b]!.radius + 90);
  }
  const packages = model.overview.nodes.filter(node => node.nodeType === "package");
  expect(new Set(packages.map(node => node.x)).size).toBe(packages.length);
  expect(new Set(packages.map(node => node.y)).size).toBe(packages.length);
  for (let a = 0; a < packages.length; a++) for (let b = a + 1; b < packages.length; b++) {
    expect(Math.hypot(packages[a]!.x - packages[b]!.x, packages[a]!.y - packages[b]!.y)).toBeGreaterThan(packages[a]!.size + packages[b]!.size);
  }
  expect(model.graph.order).toBe(nodes.length);
  expect(model.graph.edges()).toEqual(["recorded"]);
  expect(model.graph.source("recorded")).toBe("agent-000");
  expect(model.graph.target("recorded")).toBe("package-000");
});

it("keeps a bounded estate of many environment clusters finite and distinct", () => {
  const nodes = Array.from({ length: 3000 }, (_, index) => node(`node-${index}`, { dimensions: { environment: `scope-${index}` } }));
  const model = buildSigmaGraphOverviewModel(nodes, [], "environment");
  expect(model.graph.order).toBe(3000);
  expect(model.graph.size).toBe(0);
  expect(model.groups).toHaveLength(3000);
  expect(model.overview.nodes.every(node => Number.isFinite(node.x) && Number.isFinite(node.y))).toBe(true);
  expect(new Set(model.overview.nodes.map(node => `${node.x}:${node.y}`)).size).toBe(3000);
});

it("bounds a large inventory without inventing connections or losing total counts", () => {
  const nodes = Array.from({ length: 100_000 }, (_, i) => node(`asset-${i}`));
  const edges = nodes.slice(1).map((item, i) => edge(`edge-${i}`, nodes[i]!.id, item.id));
  const started = performance.now();
  const model = buildSigmaGraphOverviewModel(nodes, edges);
  console.info(`100k inventory overview projection: ${Math.round(performance.now() - started)} ms`);
  expect(model.graph.order).toBeLessThanOrEqual(3000);
  expect(model.graph.size).toBeLessThanOrEqual(6000);
  expect(model.summary.nodes).toBe(100_000);
  expect(model.overview.omittedNodeCount + model.graph.order).toBe(100_000);
  const sourceEdges = new Map(edges.map(item => [item.id, item]));
  model.graph.forEachEdge((id, _attributes, source, target) => {
    expect(sourceEdges.get(id)).toMatchObject({ source, target });
  });
});
