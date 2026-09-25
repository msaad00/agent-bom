import type { LineageNodeType } from "@/lib/entity-icons";
import { GRAPH_LAYER_ENTITY_TYPES } from "@/lib/graph-entity-mapping";

const LABEL_OVERRIDES: Partial<Record<LineageNodeType, string>> = {
  org: "Organization", ciJob: "CI/CD Job", apiGateway: "API Gateway",
};

export const NODE_LABELS = Object.fromEntries(
  (Object.keys(GRAPH_LAYER_ENTITY_TYPES) as LineageNodeType[]).map(type => [
    type, LABEL_OVERRIDES[type] ?? (type[0]!.toUpperCase() + type.slice(1)).replace(/([a-z])([A-Z])/g, "$1 $2"),
  ]),
) as Record<LineageNodeType, string>;
