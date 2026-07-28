import type { LineageNodeType } from "@/lib/entity-icons";
import { EntityType } from "@/lib/graph-schema";

/**
 * Canonical bridge between public graph layers, API entity filters, and
 * lineage renderers. A layer may intentionally own more than one backend
 * entity type (for example applications use the existing container visual).
 */
export const GRAPH_LAYER_ENTITY_TYPES: Record<
  LineageNodeType,
  readonly EntityType[]
> = {
  provider: [EntityType.PROVIDER],
  agent: [EntityType.AGENT],
  org: [EntityType.ORG],
  account: [EntityType.ACCOUNT],
  user: [EntityType.USER],
  group: [EntityType.GROUP],
  role: [EntityType.ROLE],
  policy: [EntityType.POLICY],
  serviceAccount: [EntityType.SERVICE_ACCOUNT],
  servicePrincipal: [EntityType.SERVICE_PRINCIPAL],
  federatedIdentity: [EntityType.FEDERATED_IDENTITY],
  environment: [EntityType.ENVIRONMENT],
  fleet: [EntityType.FLEET],
  cluster: [EntityType.CLUSTER],
  server: [EntityType.SERVER],
  sharedServer: [EntityType.SERVER],
  package: [EntityType.PACKAGE],
  model: [EntityType.MODEL],
  framework: [EntityType.FRAMEWORK],
  dataset: [EntityType.DATASET],
  container: [EntityType.CONTAINER, EntityType.APPLICATION],
  cloudResource: [EntityType.CLOUD_RESOURCE],
  vulnerability: [EntityType.VULNERABILITY],
  misconfiguration: [EntityType.MISCONFIGURATION],
  credential: [EntityType.CREDENTIAL],
  tool: [EntityType.TOOL],
  managedIdentity: [EntityType.MANAGED_IDENTITY],
  accessGrant: [EntityType.ACCESS_GRANT],
  accessPolicy: [EntityType.ACCESS_POLICY],
  driftIncident: [EntityType.DRIFT_INCIDENT],
  dataStore: [EntityType.DATA_STORE],
  directory: [EntityType.DIRECTORY],
  sourceFile: [EntityType.SOURCE_FILE],
  configFile: [EntityType.CONFIG_FILE],
};

const ENTITY_TO_LINEAGE_NODE_TYPE = new Map<string, LineageNodeType>();
for (const [layer, entityTypes] of Object.entries(GRAPH_LAYER_ENTITY_TYPES)) {
  for (const entityType of entityTypes) {
    // First write wins: sharedServer refines SERVER in the UI, while the
    // canonical topology renderer remains server. Applications are owned by
    // the container layer and therefore map to its existing renderer.
    if (!ENTITY_TO_LINEAGE_NODE_TYPE.has(entityType)) {
      ENTITY_TO_LINEAGE_NODE_TYPE.set(entityType, layer as LineageNodeType);
    }
  }
}

export function entityTypesForLayers(
  layers: Record<LineageNodeType, boolean>,
): EntityType[] {
  const requested = new Set<EntityType>();
  for (const [layer, enabled] of Object.entries(layers)) {
    if (!enabled) continue;
    for (const entityType of
      GRAPH_LAYER_ENTITY_TYPES[layer as LineageNodeType]) {
      requested.add(entityType);
    }
  }
  return [...requested];
}

export function lineageNodeTypeForEntity(
  entityType: EntityType | string,
): LineageNodeType | null {
  return ENTITY_TO_LINEAGE_NODE_TYPE.get(String(entityType)) ?? null;
}
