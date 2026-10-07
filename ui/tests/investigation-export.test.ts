import { describe, expect, it } from "vitest";
import { investigationExport } from "@/lib/investigation-export";
import type { ExposurePath } from "@/lib/exposure-path";

describe("bounded investigation export", () => {
  it.each([10, 1000, 10000])("exports %i supplied nodes within the visible budget with evidence limits", (size) => {
    const hops = Array.from({ length: size }, (_, index) => ({ id: `n${index}`, label: `Node ${index}`, role: "unknown" as const }));
    const path = { id: "p", hops, relationships: [{ id: "e1", source: "n0", target: "n1", relationship: "uses" }, { id: "outside", source: "n0", target: `n${size}`, relationship: "uses" }], nodeIds: hops.map(node => node.id), provenance: { source: "recorded" }, reachability: "unknown" } as ExposurePath;
    const result = investigationExport(path, "current-estate:g", "/security-graph?selected_path=p&access_token=secret");
    expect(result.path.hops.length).toBe(Math.min(size, 100));
    expect(result.path.relationships.map(rel => rel.id)).toEqual(["e1"]);
    expect(result.path.reachability).toBe("unknown");
    expect(result.path.provenance).toEqual(path.provenance);
    expect(result.scope.route).not.toContain("secret");
    expect(result.scope.kind).toBe("current_estate_generation");
    expect(result.coverage).toMatchObject({ estate_complete: false, truncated: size > 100 });
  });
});
