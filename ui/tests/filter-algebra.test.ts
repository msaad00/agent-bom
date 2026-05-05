import { describe, expect, it } from "vitest";

import {
  applyFilters,
  decodeFiltersFromParams,
  encodeFiltersToParams,
} from "@/lib/filter-algebra";
import { createExpandedGraphFilters, type FilterState } from "@/components/lineage-filter";
import {
  EntityType,
  RelationshipType,
  type UnifiedEdge,
  type UnifiedGraphData,
  type UnifiedNode,
} from "@/lib/graph-schema";
import type { UnifiedGraphResponse } from "@/lib/api";

// ───────────────────────────────────────────────────────────────────────
// Synthetic graph — 20 nodes:
//   • 3 agents (A, B, C)
//   • 3 servers (one per agent)
//   • 6 packages (2 per server)
//   • 3 credentials (one per agent)
//   • 3 tools (one per server)
//   • 2 vulnerabilities (one critical against agent-A's package, one high
//     against agent-B's package; agent-C has no findings)
//
// Edges encode the canonical inventory + attack/runtime relationships
// so each filter dimension has at least two distinguishable values.
// ───────────────────────────────────────────────────────────────────────

function node(
  id: string,
  entity_type: EntityType,
  label: string,
  severity: string = "",
  extra: Partial<UnifiedNode> = {},
): UnifiedNode {
  return {
    id,
    entity_type,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: 0,
    severity,
    severity_id: 0,
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: "2026-01-01T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    data_sources: [],
    dimensions: {},
    ...extra,
  };
}

function edge(
  source: string,
  target: string,
  relationship: RelationshipType,
  direction: "directed" | "bidirectional" = "directed",
): UnifiedEdge {
  return {
    id: `${source}->${relationship}->${target}`,
    source,
    target,
    relationship,
    direction,
    weight: 1,
    traversable: true,
    first_seen: "2026-01-01T00:00:00Z",
    last_seen: "2026-01-01T00:00:00Z",
    evidence: {},
    activity_id: 0,
  };
}

function buildSyntheticGraph(): UnifiedGraphResponse {
  const nodes: UnifiedNode[] = [
    // Agents
    node("agent-A", EntityType.AGENT, "Agent A"),
    node("agent-B", EntityType.AGENT, "Agent B"),
    node("agent-C", EntityType.AGENT, "Agent C"),
    // Servers
    node("server-A", EntityType.SERVER, "Server A"),
    node("server-B", EntityType.SERVER, "Server B"),
    node("server-C", EntityType.SERVER, "Server C"),
    // Packages — 2 per server
    node("pkg-A1", EntityType.PACKAGE, "pkg-A1"),
    node("pkg-A2", EntityType.PACKAGE, "pkg-A2"),
    node("pkg-B1", EntityType.PACKAGE, "pkg-B1"),
    node("pkg-B2", EntityType.PACKAGE, "pkg-B2"),
    node("pkg-C1", EntityType.PACKAGE, "pkg-C1"),
    node("pkg-C2", EntityType.PACKAGE, "pkg-C2"),
    // Credentials
    node("cred-A", EntityType.CREDENTIAL, "cred-A"),
    node("cred-B", EntityType.CREDENTIAL, "cred-B"),
    node("cred-C", EntityType.CREDENTIAL, "cred-C"),
    // Tools
    node("tool-A", EntityType.TOOL, "tool-A"),
    node("tool-B", EntityType.TOOL, "tool-B"),
    node("tool-C", EntityType.TOOL, "tool-C"),
    // Findings — 2 vulnerabilities
    node("cve-1", EntityType.VULNERABILITY, "CVE-2026-0001", "critical"),
    node("cve-2", EntityType.VULNERABILITY, "CVE-2026-0002", "high"),
  ];

  const edges: UnifiedEdge[] = [
    // agent uses server (inventory)
    edge("agent-A", "server-A", RelationshipType.USES),
    edge("agent-B", "server-B", RelationshipType.USES),
    edge("agent-C", "server-C", RelationshipType.USES),
    // server depends on packages (inventory)
    edge("server-A", "pkg-A1", RelationshipType.DEPENDS_ON),
    edge("server-A", "pkg-A2", RelationshipType.DEPENDS_ON),
    edge("server-B", "pkg-B1", RelationshipType.DEPENDS_ON),
    edge("server-B", "pkg-B2", RelationshipType.DEPENDS_ON),
    edge("server-C", "pkg-C1", RelationshipType.DEPENDS_ON),
    edge("server-C", "pkg-C2", RelationshipType.DEPENDS_ON),
    // server provides tool
    edge("server-A", "tool-A", RelationshipType.PROVIDES_TOOL),
    edge("server-B", "tool-B", RelationshipType.PROVIDES_TOOL),
    edge("server-C", "tool-C", RelationshipType.PROVIDES_TOOL),
    // server exposes credential
    edge("server-A", "cred-A", RelationshipType.EXPOSES_CRED),
    edge("server-B", "cred-B", RelationshipType.EXPOSES_CRED),
    edge("server-C", "cred-C", RelationshipType.EXPOSES_CRED),
    // package vulnerable to CVE (attack)
    edge("pkg-A1", "cve-1", RelationshipType.VULNERABLE_TO),
    edge("pkg-B1", "cve-2", RelationshipType.VULNERABLE_TO),
    // attack edges so the relationships=attack scope is non-empty
    edge("cve-1", "agent-A", RelationshipType.AFFECTS),
    edge("cve-2", "agent-B", RelationshipType.AFFECTS),
    // runtime invocation (so runtime mode has signal)
    edge("agent-A", "tool-A", RelationshipType.INVOKED),
  ];

  const data: UnifiedGraphData = {
    scan_id: "synthetic-scan",
    tenant_id: "synthetic-tenant",
    created_at: "2026-01-01T00:00:00Z",
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
  return {
    ...data,
    pagination: { total: nodes.length, offset: 0, limit: nodes.length, has_more: false },
  };
}

function wideFilters(): FilterState {
  return createExpandedGraphFilters(null);
}

// Helper: serialise a Set in stable sort order so snapshots are deterministic.
function snapshotValid(v: {
  severities: Set<string>;
  agents: Set<string>;
  layers: Set<string>;
  relationships: Set<string>;
}) {
  return {
    severities: [...v.severities].sort(),
    agents: [...v.agents].sort(),
    layers: [...v.layers].sort(),
    relationships: [...v.relationships].sort(),
  };
}

describe("applyFilters — constraint propagation", () => {
  const graph = buildSyntheticGraph();

  it("[1] no filters → all 20 nodes returned, all valid values populated", () => {
    const result = applyFilters(graph, wideFilters());
    expect(result.nodes).toHaveLength(20);
    expect(snapshotValid(result.validValues)).toEqual({
      severities: ["critical", "high"],
      agents: ["Agent A", "Agent B", "Agent C"],
      // every layer with at least one node in the graph
      layers: [
        "agent",
        "credential",
        "package",
        "server",
        "tool",
        "vulnerability",
      ],
      // every distinct edge.relationship that connects two surviving nodes
      relationships: [
        "affects",
        "depends_on",
        "exposes_cred",
        "invoked",
        "provides_tool",
        "uses",
        "vulnerable_to",
      ],
    });
  });

  it("[2] severity=critical only → only critical-pass nodes; agents narrowed", () => {
    const filters: FilterState = { ...wideFilters(), severity: "critical" };
    const result = applyFilters(graph, filters);
    // The severity predicate keeps every non-finding node (no severity)
    // and only the critical CVE — so cve-2 (high) is dropped, total = 19.
    expect(result.nodes).toHaveLength(19);
    expect(result.nodes.some((n) => n.id === "cve-1")).toBe(true);
    expect(result.nodes.some((n) => n.id === "cve-2")).toBe(false);

    // severity validValues — would be reachable if user toggled severity
    // back, with all OTHER filters held. So both severities are valid.
    expect(snapshotValid(result.validValues)).toEqual({
      severities: ["critical", "high"],
      // Agents valid given severity=critical: only Agent A reaches cve-1.
      // Agent B and Agent C still have inventory; the algebra reports
      // every agent whose neighborhood is non-empty under the OTHER
      // filters — which here is "all 3" because severity is dropped when
      // computing valid agents.
      agents: ["Agent A", "Agent B", "Agent C"],
      layers: [
        "agent",
        "credential",
        "package",
        "server",
        "tool",
        "vulnerability",
      ],
      relationships: [
        "affects",
        "depends_on",
        "exposes_cred",
        "invoked",
        "provides_tool",
        "uses",
        "vulnerable_to",
      ],
    });
  });

  it("[3] agent=A only → only A's neighborhood; severities reflect A's findings", () => {
    const filters: FilterState = { ...wideFilters(), agentName: "Agent A" };
    const result = applyFilters(graph, filters);
    // Agent A's neighborhood at depth 6 reaches:
    // agent-A, server-A, pkg-A1, pkg-A2, tool-A, cred-A, cve-1, plus
    // cve-1 -> agent-A (already in). Total 7.
    expect(result.nodes).toHaveLength(7);
    expect(new Set(result.nodes.map((n) => n.id))).toEqual(
      new Set(["agent-A", "server-A", "pkg-A1", "pkg-A2", "tool-A", "cred-A", "cve-1"]),
    );

    expect(snapshotValid(result.validValues)).toEqual({
      // Only critical reachable from Agent A (via pkg-A1 → cve-1).
      severities: ["critical"],
      agents: ["Agent A", "Agent B", "Agent C"],
      // Layers reachable from A — no misconfiguration, no providers/etc.
      layers: ["agent", "credential", "package", "server", "tool", "vulnerability"],
      relationships: [
        "affects",
        "depends_on",
        "exposes_cred",
        "invoked",
        "provides_tool",
        "uses",
        "vulnerable_to",
      ],
    });
  });

  it("[4] severity=high + agent=C → empty CVE set; valid values reflect that", () => {
    const filters: FilterState = {
      ...wideFilters(),
      severity: "high",
      agentName: "Agent C",
    };
    const result = applyFilters(graph, filters);
    // Agent C reaches: agent-C, server-C, pkg-C1, pkg-C2, tool-C, cred-C.
    // No CVE in C's neighborhood, so the severity:high predicate drops
    // nothing further (the non-finding nodes have no severity and pass).
    expect(result.nodes).toHaveLength(6);
    expect(result.nodes.every((n) => n.entity_type !== EntityType.VULNERABILITY)).toBe(true);

    expect(snapshotValid(result.validValues)).toEqual({
      // Severities reachable in Agent C's neighborhood with severity
      // dropped — empty (C has no findings).
      severities: [],
      agents: ["Agent A", "Agent B", "Agent C"],
      // Layers reachable in C's neighborhood (no vulnerability).
      layers: ["agent", "credential", "package", "server", "tool"],
      relationships: ["depends_on", "exposes_cred", "provides_tool", "uses"],
    });
  });

  it("[5] relationships=attack only → only attack-edge subgraph", () => {
    const filters: FilterState = { ...wideFilters(), relationshipScope: "attack" };
    const result = applyFilters(graph, filters);
    // attack edges: VULNERABLE_TO ×2, AFFECTS ×2.
    // Surviving nodes are only those connected by attack edges:
    // pkg-A1, pkg-B1, cve-1, cve-2, agent-A, agent-B (via AFFECTS).
    // Other nodes still PASS the layer + severity + vulnOnly + agent
    // predicates so they remain in `nodes` — but the algebra prunes
    // edges to attack-scope only. So node count is unchanged (no
    // node-level attack predicate).
    expect(result.nodes).toHaveLength(20);
    // But every surviving edge must be attack scope.
    const allowed = new Set([
      "affects",
      "vulnerable_to",
      "exploitable_via",
      "remediates",
      "triggers",
      "shares_server",
      "shares_cred",
      "lateral_path",
    ]);
    for (const e of result.edges) {
      expect(allowed.has(String(e.relationship))).toBe(true);
    }
    expect(result.edges).toHaveLength(4); // 2 VULNERABLE_TO + 2 AFFECTS

    expect(snapshotValid(result.validValues)).toEqual({
      severities: ["critical", "high"],
      agents: ["Agent A", "Agent B", "Agent C"],
      layers: [
        "agent",
        "credential",
        "package",
        "server",
        "tool",
        "vulnerability",
      ],
      // relationships valid — drops the scope, returns every edge kind
      // present given the OTHER filters.
      relationships: [
        "affects",
        "depends_on",
        "exposes_cred",
        "invoked",
        "provides_tool",
        "uses",
        "vulnerable_to",
      ],
    });
  });

  it("returns empty result for empty graph", () => {
    const result = applyFilters(null, wideFilters());
    expect(result.nodes).toEqual([]);
    expect(result.edges).toEqual([]);
    expect(result.validValues.agents.size).toBe(0);
  });
});

describe("URL state codec", () => {
  it("round-trips a representative filter combination", () => {
    const filters: FilterState = {
      ...wideFilters(),
      severity: "high",
      agentName: "claude-desktop",
      maxDepth: 4,
      relationshipScope: "attack",
    };
    const params = encodeFiltersToParams(filters);
    expect(params.get("severity")).toBe("high");
    expect(params.get("agent")).toBe("claude-desktop");
    expect(params.get("depth")).toBe("4");
    expect(params.get("relationships")).toBe("attack");

    const decoded = decodeFiltersFromParams(params);
    expect(decoded.severity).toBe("high");
    expect(decoded.agentName).toBe("claude-desktop");
    expect(decoded.maxDepth).toBe(4);
    expect(decoded.relationshipScope).toBe("attack");
  });

  it("ignores unknown / malformed values", () => {
    const params = new URLSearchParams("relationships=garbage&depth=abc&pageSize=-1");
    const patch = decodeFiltersFromParams(params);
    expect(patch.relationshipScope).toBeUndefined();
    expect(patch.maxDepth).toBeUndefined();
    expect(patch.pageSize).toBeUndefined();
  });
});
