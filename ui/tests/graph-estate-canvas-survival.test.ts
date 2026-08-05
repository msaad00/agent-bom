import { describe, expect, it } from "vitest";

import { EXPANDED_LAYER_DEFAULTS } from "@/components/lineage-filter";
import {
  EntityType,
  RelationshipType,
  type UnifiedEdge,
  type UnifiedGraphData,
  type UnifiedNode,
} from "@/lib/graph-schema";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";

/**
 * `graph-schema-canvas-coverage.test.ts` proves every backend `EntityType` has a
 * lineage mapping and a registered renderer. That is necessary, not sufficient:
 * the drop happens inside `buildUnifiedFlowGraph`, which skips a node whose type
 * resolves to null and then prunes every edge touching it (#4640, api_gateway /
 * PROTECTS). That regression was pinned for one entity type only.
 *
 * The enterprise demo estate is now projected into the graph, so a single
 * snapshot carries org / account / environment / cluster / data_store /
 * service_account / service_principal / role / application / ci_job /
 * misconfiguration nodes wired by CONTAINS, AFFECTS, CAN_ACCESS and ACCESSED —
 * types and relationships the 112-node showcase never exercised end to end.
 * Rather than pin that list (which drifts the moment the projection grows), walk
 * the whole backend schema through the real builder and assert nothing is lost.
 */

const ENTITY_TYPES = Object.values(EntityType);
const RELATIONSHIP_TYPES = Object.values(RelationshipType);

function node(entityType: EntityType): UnifiedNode {
  return {
    id: `${entityType}:probe`,
    entity_type: entityType,
    label: `${entityType} probe`,
    category_uid: 5,
    class_uid: 4001,
    type_uid: 400101,
    status: "active",
    risk_score: 0,
    severity: "none",
    severity_id: 0,
    first_seen: "2026-08-01T00:00:00Z",
    last_seen: "2026-08-01T00:00:00Z",
    attributes: {},
    compliance_tags: [],
    data_sources: [],
    dimensions: {} as UnifiedNode["dimensions"],
  };
}

function edge(
  source: string,
  target: string,
  relationship: RelationshipType,
): UnifiedEdge {
  return {
    id: `${source}:${relationship}:${target}`,
    source,
    target,
    relationship,
    direction: "directed",
    weight: 1,
    traversable: true,
    first_seen: "2026-08-01T00:00:00Z",
    last_seen: "2026-08-01T00:00:00Z",
    evidence: {},
    activity_id: 1,
  };
}

// One node per entity type, and one edge per relationship type laid over them so
// every node is connected and no relationship is unrepresented.
const nodes = ENTITY_TYPES.map(node);
const edges = RELATIONSHIP_TYPES.map((relationship, index) =>
  edge(
    `${ENTITY_TYPES[index % ENTITY_TYPES.length]}:probe`,
    `${ENTITY_TYPES[(index + 1) % ENTITY_TYPES.length]}:probe`,
    relationship,
  ),
);

const graph: UnifiedGraphData = {
  scan_id: "estate-survival",
  tenant_id: "default",
  created_at: "2026-08-01T00:00:00Z",
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

const flow = buildUnifiedFlowGraph(graph, {
  layers: { ...EXPANDED_LAYER_DEFAULTS },
  severity: null,
  agentName: null,
  vulnOnly: false,
  maxDepth: 3,
});

describe("every backend entity and relationship survives the canvas builder", () => {
  it("renders a node for every backend EntityType", () => {
    const rendered = new Set(flow.nodes.map((entry) => entry.id));
    const dropped = ENTITY_TYPES.filter(
      (entityType) => !rendered.has(`${entityType}:probe`),
    );
    expect(dropped).toEqual([]);
  });

  it("gives every rendered node a concrete React Flow renderer", () => {
    const untyped = flow.nodes.filter((entry) => !entry.type);
    expect(untyped.map((entry) => entry.id)).toEqual([]);
  });

  it("keeps an edge for every backend RelationshipType", () => {
    const rendered = new Set(
      flow.edges.map((entry) => String(entry.data?.relationship ?? "")),
    );
    const dropped = RELATIONSHIP_TYPES.filter(
      (relationship) => !rendered.has(relationship),
    );
    expect(dropped).toEqual([]);
  });

  it("keeps the estate hierarchy and posture relationships specifically", () => {
    // The four the projected estate leans on: the containment spine the roll-up
    // walks, the finding→asset correlation, the principal→resource claim, and
    // the observed incident chain.
    const rendered = new Set(
      flow.edges.map((entry) => String(entry.data?.relationship ?? "")),
    );
    for (const relationship of [
      RelationshipType.CONTAINS,
      RelationshipType.AFFECTS,
      RelationshipType.CAN_ACCESS,
      RelationshipType.ACCESSED,
    ]) {
      expect(rendered.has(relationship)).toBe(true);
    }
  });

  it("keeps the estate's own entity types specifically", () => {
    const rendered = new Set(flow.nodes.map((entry) => entry.id));
    for (const entityType of [
      EntityType.ORG,
      EntityType.ACCOUNT,
      EntityType.ENVIRONMENT,
      EntityType.CLUSTER,
      EntityType.DATA_STORE,
      EntityType.ROLE,
      EntityType.SERVICE_ACCOUNT,
      EntityType.SERVICE_PRINCIPAL,
      EntityType.APPLICATION,
      EntityType.CI_JOB,
      EntityType.CONTAINER,
      EntityType.MISCONFIGURATION,
      EntityType.MODEL,
    ]) {
      expect(rendered.has(`${entityType}:probe`)).toBe(true);
    }
  });
});
