/**
 * Audit-4 P1 invariant: every Python RelationshipType value must have an
 * entry in the dashboard's RELATIONSHIP_COLOR_MAP. The Python schema
 * parity test (tests/test_graph_schema_ui_parity.py) already locks the
 * UI enum values to the Python ones; this test pins the second half —
 * the color map — so a freshly added relationship type can never ship
 * to the dashboard without an explicit color and edges in the graph
 * never silently fall back to whatever the renderer's default is.
 */

import { describe, expect, it } from "vitest";

import {
  ENTITY_COLOR_MAP,
  EntityType,
  GRAPH_NODE_KIND_META,
  RELATIONSHIP_COLOR_MAP,
  RelationshipType,
} from "@/lib/graph-schema";
import {
  ATTACK_FLOW_MINIMAP_COLORS,
  ATTACK_FLOW_NODE_CLASS_MAP,
  LINEAGE_NODE_GRAPH_KIND,
  NODE_COLOR_MAP,
} from "@/lib/graph-utils";

describe("RELATIONSHIP_COLOR_MAP", () => {
  it("has a color for every RelationshipType", () => {
    const missing: string[] = [];
    for (const value of Object.values(RelationshipType)) {
      if (typeof value !== "string") continue;
      if (RELATIONSHIP_COLOR_MAP[value] === undefined) {
        missing.push(value);
      }
    }
    expect(missing).toEqual([]);
  });

  it("maps each color to a hex string", () => {
    const bad: string[] = [];
    for (const [key, color] of Object.entries(RELATIONSHIP_COLOR_MAP)) {
      if (!/^#[0-9a-fA-F]{3,8}$/.test(color)) {
        bad.push(`${key}=${color}`);
      }
    }
    expect(bad).toEqual([]);
  });
});

describe("GRAPH_NODE_KIND_META", () => {
  it("has label, color, shape, and semantic layer for every node kind", () => {
    const bad: string[] = [];
    for (const [key, meta] of Object.entries(GRAPH_NODE_KIND_META)) {
      if (!meta.label || !meta.shape || !meta.layer || !/^#[0-9a-fA-F]{3,8}$/.test(meta.color)) {
        bad.push(key);
      }
    }
    expect(bad).toEqual([]);
  });
});

describe("LINEAGE_NODE_GRAPH_KIND", () => {
  it("maps emitted governance node kinds to generated schema colors", () => {
    const emittedGovernanceKinds = [
      "org",
      "account",
      "role",
      "policy",
      "servicePrincipal",
      "federatedIdentity",
    ] as const;

    const mismatches = emittedGovernanceKinds.flatMap((lineageKind) => {
      const graphKind = LINEAGE_NODE_GRAPH_KIND[lineageKind];
      if (!graphKind) return [`${lineageKind}:missing-kind`];
      const expected = GRAPH_NODE_KIND_META[graphKind]?.color;
      const actual = NODE_COLOR_MAP[lineageKind];
      return actual === expected ? [] : [`${lineageKind}:${actual ?? "missing"}!=${expected ?? "missing"}`];
    });

    expect(mismatches).toEqual([]);
  });

  it("uses one credential color across lineage and attack-flow views", () => {
    expect(NODE_COLOR_MAP.credential).toBe(ENTITY_COLOR_MAP[EntityType.CREDENTIAL]);
    expect(ATTACK_FLOW_MINIMAP_COLORS.credential).toBe(ENTITY_COLOR_MAP[EntityType.CREDENTIAL]);
  });

  it("keeps attack-flow node backgrounds readable in light and dark themes", () => {
    for (const [nodeType, classes] of Object.entries(ATTACK_FLOW_NODE_CLASS_MAP)) {
      const hasPalettePair = /\bbg-[a-z]+-50/.test(classes) && /\bdark:bg-[a-z]+-950/.test(classes);
      const hasThemeSurface = classes.includes("bg-[color:var(--surface-elevated)]");
      expect(hasPalettePair || hasThemeSurface, nodeType).toBe(true);
    }
  });
});
