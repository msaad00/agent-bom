import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { GraphRollupContainer } from "@/lib/api-types";

const ROLLUP_ENTITY_TO_NODE_TYPE: Record<string, LineageNodeType> = {
  provider: "provider",
  org: "org",
  account: "account",
  user: "user",
  group: "group",
  role: "role",
  policy: "policy",
  service_account: "serviceAccount",
  service_principal: "servicePrincipal",
  federated_identity: "federatedIdentity",
  environment: "environment",
  fleet: "fleet",
  cluster: "cluster",
  application: "container",
  server: "server",
  package: "package",
  tool: "tool",
  credential: "credential",
  vulnerability: "vulnerability",
  misconfiguration: "misconfiguration",
  model: "model",
  framework: "framework",
  dataset: "dataset",
  container: "container",
  cloud_resource: "cloudResource",
  managed_identity: "managedIdentity",
  access_grant: "accessGrant",
  access_policy: "accessPolicy",
  drift_incident: "driftIncident",
  data_store: "dataStore",
  directory: "directory",
  source_file: "sourceFile",
  config_file: "configFile",
  agent: "agent",
};

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
};

const DEFAULT_COLUMNS = 3;
const NODE_WIDTH = 268;
const NODE_HEIGHT = 112;

export function rollupEntityToNodeType(entityType: string): LineageNodeType {
  return ROLLUP_ENTITY_TO_NODE_TYPE[entityType] ?? "cloudResource";
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

export function buildRollupFlowGraph(
  containers: GraphRollupContainer[],
  options?: { columns?: number },
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
  return { nodes, edges: [] };
}
