import { describe, expect, it } from "vitest";

import {
  EXPANDED_LAYER_DEFAULTS,
  LAYER_LABELS,
} from "@/components/lineage-filter";
import { ENTITY_ICONS, type LineageNodeType } from "@/lib/entity-icons";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";
import {
  EntityType,
  RelationshipType,
  type UnifiedEdge,
  type UnifiedGraphData,
  type UnifiedNode,
} from "@/lib/graph-schema";
import {
  NODE_TYPE_LEGEND_ORDER,
  RELATIONSHIP_LEGEND_ORDER,
  legendItemForNodeType,
  relationshipLegendItemsForVisibleEdges,
} from "@/lib/graph-utils";
import {
  buildUnifiedFlowGraph,
  flowRendererTypeForEntity,
} from "@/lib/unified-graph-flow";
import { lineageNodeTypesAdaptive } from "@/components/lineage-nodes";

/**
 * The graph canvas drops any node whose entity type has no lineage mapping
 * (`unified-graph-flow.ts` skips `mapNodeType(node) === null`), taking every
 * edge that touches it with it. These assertions walk the BACKEND enums —
 * kept byte-equal to Python by `tests/test_graph_schema_ui_parity.py` — rather
 * than the UI's own layer subset, so a new backend entity or relationship can
 * never land on the canvas as a silent omission.
 */
describe("backend graph schema is fully representable on the canvas", () => {
  const allLineageNodeTypes = Object.keys(ENTITY_ICONS) as LineageNodeType[];

  it("maps every backend EntityType to a lineage node type", () => {
    const unmapped = Object.values(EntityType).filter(
      (entityType) => lineageNodeTypeForEntity(entityType) === null,
    );
    expect(unmapped).toEqual([]);
  });

  it("gives every backend EntityType a registered flow renderer", () => {
    const unrenderable = Object.values(EntityType).filter((entityType) => {
      const renderer = flowRendererTypeForEntity(entityType);
      return !renderer || !(renderer in lineageNodeTypesAdaptive);
    });
    expect(unrenderable).toEqual([]);
  });

  it("lists every lineage node type in the on-canvas legend order", () => {
    const missing = allLineageNodeTypes.filter(
      (nodeType) => !NODE_TYPE_LEGEND_ORDER.includes(nodeType),
    );
    expect(missing).toEqual([]);
  });

  it("gives every lineage node type a visibility toggle", () => {
    const toggled = new Set(LAYER_LABELS.map((entry) => entry.key));
    const missing = allLineageNodeTypes.filter(
      (nodeType) => !toggled.has(nodeType),
    );
    expect(missing).toEqual([]);
  });

  it("labels every visibility toggle distinctly", () => {
    const labels = LAYER_LABELS.map((entry) => entry.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("lists every backend RelationshipType in the edge legend order", () => {
    const order = new Set<string>(RELATIONSHIP_LEGEND_ORDER);
    const missing = Object.values(RelationshipType).filter(
      (relationship) => !order.has(relationship),
    );
    expect(missing).toEqual([]);
  });
});

function node(id: string, entityType: EntityType, label: string): UnifiedNode {
  return {
    id,
    entity_type: entityType,
    label,
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

/**
 * Regression for the exposure-mitigation story: `build_unified_graph_from_report`
 * emits an `api_gateway` node from AWS / Azure / GCP inventory and links it to
 * the resource it fronts with PROTECTS. While the gateway had no lineage
 * mapping the canvas dropped the node AND pruned the PROTECTS edge with it, so
 * a WAF-fronted resource looked identical to a bare one.
 */
describe("api gateway exposure mitigation survives the canvas", () => {
  const graph: UnifiedGraphData = {
    scan_id: "scan-1",
    tenant_id: "tenant-1",
    created_at: "2026-08-01T00:00:00Z",
    nodes: [
      node("api_gateway:aws:api-1", EntityType.API_GATEWAY, "aws-apigw"),
      node("cloud_resource:aws:fn-1", EntityType.CLOUD_RESOURCE, "orders-fn"),
    ],
    edges: [
      edge(
        "api_gateway:aws:api-1",
        "cloud_resource:aws:fn-1",
        RelationshipType.PROTECTS,
      ),
    ],
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: 2,
      total_edges: 1,
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

  it("keeps the gateway node and its PROTECTS edge on the canvas", () => {
    expect(flow.nodes.map((entry) => entry.id)).toEqual([
      "api_gateway:aws:api-1",
      "cloud_resource:aws:fn-1",
    ]);
    expect(flow.edges).toHaveLength(1);
    expect(flow.edges[0]?.data).toMatchObject({ relationship: "protects" });
  });

  it("renders the gateway with its own label and renderer", () => {
    const gateway = flow.nodes.find(
      (entry) => entry.id === "api_gateway:aws:api-1",
    );
    expect(gateway?.data.nodeType).toBe("apiGateway");
    expect(gateway?.type).toBe("cloudResourceNode");
    expect(flow.legend.map((item) => item.label)).toContain("API Gateway");
  });

  it("gives the PROTECTS edge a legend row", () => {
    const rows = relationshipLegendItemsForVisibleEdges(flow.edges);
    expect(rows.map((item) => item.label)).toContain("Protects (WAF/gateway)");
  });

  it("keys the gateway legend row off the generated schema, not a fallback", () => {
    // "#52525b" is the neutral fallback `legendItemForNodeType` falls back to
    // when a lineage type has no generated node-kind behind it.
    expect(legendItemForNodeType("apiGateway")).toMatchObject({
      label: "API Gateway",
      color: "#2563eb",
      layer: "api_gateway",
      nodeType: "apiGateway",
    });
  });
});
