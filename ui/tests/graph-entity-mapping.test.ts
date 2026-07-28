import { describe, expect, it } from "vitest";

import { EXPANDED_LAYER_DEFAULTS } from "@/components/lineage-filter";
import {
  GRAPH_LAYER_ENTITY_TYPES,
  entityTypesForLayers,
  lineageNodeTypeForEntity,
} from "@/lib/graph-entity-mapping";
import { EntityType } from "@/lib/graph-schema";
import { flowRendererTypeForEntity } from "@/lib/unified-graph-flow";
import { lineageNodeTypesAdaptive } from "@/components/lineage-nodes";

describe("canonical graph entity mapping", () => {
  it("gives every enabled public layer a supported API entity type", () => {
    for (const [layer, enabled] of Object.entries(EXPANDED_LAYER_DEFAULTS)) {
      if (!enabled) continue;
      expect(GRAPH_LAYER_ENTITY_TYPES[layer as keyof typeof GRAPH_LAYER_ENTITY_TYPES]).not.toHaveLength(0);
    }
  });

  it("requests every identity and estate type and can render every request", () => {
    const requested = entityTypesForLayers(EXPANDED_LAYER_DEFAULTS);
    expect(requested).toEqual(
      expect.arrayContaining([
        EntityType.ORG,
        EntityType.ACCOUNT,
        EntityType.ROLE,
        EntityType.POLICY,
        EntityType.SERVICE_PRINCIPAL,
        EntityType.FEDERATED_IDENTITY,
        EntityType.APPLICATION,
      ]),
    );
    expect(new Set(requested).size).toBe(requested.length);
    for (const entityType of requested) {
      expect(lineageNodeTypeForEntity(entityType)).not.toBeNull();
      const renderer = flowRendererTypeForEntity(entityType);
      expect(renderer).not.toBeNull();
      expect(renderer && renderer in lineageNodeTypesAdaptive).toBe(true);
    }
  });

  it("uses the existing container visual for applications and canonical server visual for aliases", () => {
    expect(lineageNodeTypeForEntity(EntityType.APPLICATION)).toBe("container");
    expect(lineageNodeTypeForEntity(EntityType.SERVER)).toBe("server");
  });
});
