import { describe, expect, it } from "vitest";
import { investigationHref, investigationView } from "@/lib/investigation-url";

describe("investigation URL state", () => {
  it("preserves finding and snapshot scope while sharing a path and view", () => {
    const href = investigationHref("/security-graph", "scan=s%2F1&finding=f&lens=attack-path", { selected_path: "a::b", path_view: "graph" });
    const params = new URL(href, "http://fixture").searchParams;
    expect(Object.fromEntries(params)).toEqual({ scan: "s/1", finding: "f", lens: "attack-path", selected_path: "a::b", path_view: "graph" });
    expect(investigationHref("/security-graph", "path_view=graph", { path_view: null })).toBe("/security-graph");
  });
  it("ignores unsupported views", () => {
    expect(investigationView("list")).toBe("list");
    expect(investigationView("full-estate")).toBe("path");
  });
});
