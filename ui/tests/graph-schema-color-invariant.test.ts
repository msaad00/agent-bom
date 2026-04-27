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

import { RELATIONSHIP_COLOR_MAP, RelationshipType } from "@/lib/graph-schema";

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
