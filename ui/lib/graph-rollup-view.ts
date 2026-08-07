import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { GraphRollupContainer, GraphRollupEdge } from "@/lib/api-types";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";

const FLOW_NODE_TYPES: Record<LineageNodeType, string> = {
  provider: "providerNode",
  agent: "agentNode",
  org: "providerNode",
  account: "providerNode",
  user: "userNode",
  group: "groupNode",
  role: "credentialNode",
  policy: "credentialNode",
  serviceAccount: "serviceAccountNode",
  servicePrincipal: "serviceAccountNode",
  federatedIdentity: "serviceAccountNode",
  environment: "environmentNode",
  fleet: "fleetNode",
  cluster: "clusterNode",
  server: "serverNode",
  sharedServer: "sharedServerNode",
  package: "packageNode",
  vulnerability: "vulnNode",
  credential: "credentialNode",
  tool: "toolNode",
  model: "modelNode",
  framework: "frameworkNode",
  dataset: "datasetNode",
  container: "containerNode",
  cloudResource: "cloudResourceNode",
  misconfiguration: "misconfigNode",
  managedIdentity: "managedIdentityNode",
  accessGrant: "accessGrantNode",
  accessPolicy: "accessPolicyNode",
  driftIncident: "driftIncidentNode",
  dataStore: "dataStoreNode",
  directory: "containerNode",
  sourceFile: "packageNode",
  configFile: "packageNode",
  codeModule: "packageNode",
  ciJob: "toolNode",
  apiGateway: "cloudResourceNode",
  toolCall: "toolNode",
  blueprint: "accessPolicyNode",
};

const DEFAULT_COLUMNS = 3;
// NodeCard renders up to 300px wide. Position columns by the rendered maximum
// plus a deliberate gutter so long roll-up labels never overlap their neighbor.
const NODE_CARD_MAX_WIDTH = 300;
const NODE_COLUMN_GAP = 32;
const NODE_WIDTH = NODE_CARD_MAX_WIDTH + NODE_COLUMN_GAP;
const NODE_HEIGHT = 112;

export function rollupEntityToNodeType(entityType: string): LineageNodeType {
  return lineageNodeTypeForEntity(entityType) ?? "cloudResource";
}

export function rollupContainerSubtitle(container: GraphRollupContainer): string {
  const parts: string[] = [];
  const aggregate = container.aggregate;
  const descendants = aggregate?.descendant_count ?? 0;
  if (descendants > 0) {
    parts.push(
      `${descendants} descendant${descendants === 1 ? "" : "s"}`,
    );
  } else if (container.direct_child_count > 0) {
    parts.push(
      `${container.direct_child_count} direct child${container.direct_child_count === 1 ? "" : "ren"}`,
    );
  }
  if (aggregate?.worst_severity && aggregate.worst_severity !== "none") {
    parts.push(`worst ${aggregate.worst_severity}`);
  }
  if (aggregate?.internet_exposed) {
    parts.push("internet exposed");
  }
  if (aggregate?.toxic_combo) {
    parts.push("toxic combo");
  }
  if (container.has_children) {
    parts.push("click to drill down");
  }
  return parts.join(" · ");
}

function rollupContainerToNodeData(
  container: GraphRollupContainer,
): LineageNodeData {
  const nodeType = rollupEntityToNodeType(container.entity_type);
  const aggregate = container.aggregate;
  return {
    label: container.label,
    nodeType,
    entityType: container.entity_type,
    severity: container.severity || aggregate?.worst_severity || undefined,
    description: rollupContainerSubtitle(container),
    attributes: {
      node_id: container.id,
      rollup_has_children: container.has_children,
      rollup_is_container: container.is_container,
      rollup_descendant_count: aggregate?.descendant_count ?? 0,
    },
    highlighted: (aggregate?.worst_severity_rank ?? 0) >= 4,
    isCritical: aggregate?.worst_severity === "critical",
  };
}

/** Stroke width scaled to how many underlying edges collapsed into this one, so
 *  a 35-edge relationship reads as heavier than a 1-edge one at a glance. */
function rollupEdgeWidth(count: number): number {
  if (count >= 25) return 3;
  if (count >= 10) return 2.25;
  if (count >= 3) return 1.6;
  return 1;
}

export function buildRollupFlowGraph(
  containers: GraphRollupContainer[],
  options?: { columns?: number; edges?: GraphRollupEdge[] | undefined },
): { nodes: Node<LineageNodeData>[]; edges: Edge[] } {
  const columns = Math.max(1, options?.columns ?? DEFAULT_COLUMNS);
  const nodes: Node<LineageNodeData>[] = containers.map((container, index) => {
    const nodeType = rollupEntityToNodeType(container.entity_type);
    const col = index % columns;
    const row = Math.floor(index / columns);
    return {
      id: container.id,
      type: FLOW_NODE_TYPES[nodeType],
      position: { x: col * NODE_WIDTH, y: row * NODE_HEIGHT },
      data: rollupContainerToNodeData(container),
      ...(container.has_children ? { className: "cursor-pointer" } : {}),
    };
  });
  // The roll-up used to return no edges at all, so the canvas drew a grid of
  // disconnected cards and the view had to tell the reader that "aggregate
  // cards are not rendered relationship evidence" — a security graph admitting
  // it was not showing a graph. The API now aggregates the non-containment
  // edges between containers; drawing them is what makes this a topology.
  const present = new Set(nodes.map((node) => node.id));
  const edges: Edge[] = (options?.edges ?? [])
    .filter((edge) => present.has(edge.source) && present.has(edge.target))
    .map((edge) => ({
      id: `rollup:${edge.source}->${edge.target}`,
      source: edge.source,
      target: edge.target,
      // The relationship names, not just a number: "accessed x35" says what the
      // weight is made of, where a bare 35 does not.
      label: edge.count > 1 ? `${edge.relationships[0] ?? "related"} ×${edge.count}` : (edge.relationships[0] ?? "related"),
      animated: false,
      style: { strokeWidth: rollupEdgeWidth(edge.count) },
    }));
  return { nodes, edges };
}
