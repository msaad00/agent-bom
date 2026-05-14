import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const GUARDED_GRAPH_SURFACES = [
  "components/graph-chrome.tsx",
  "components/lineage-filter.tsx",
] as const;

const DARK_ONLY_SURFACE_CLASS =
  /\b(?:bg|border)-zinc-(?:700|800|900|950)(?:\/\d+)?\b|\btext-zinc-(?:100|200|300|400|500|600)(?:\/\d+)?\b|\b(?:bg-black|text-white|shadow-black)(?:\/\d+)?\b/g;

describe("light theme token guard", () => {
  it("keeps shared graph chrome and filters on theme tokens instead of dark-only panels", () => {
    const violations = GUARDED_GRAPH_SURFACES.flatMap((file) => {
      const source = readFileSync(path.join(process.cwd(), file), "utf8");
      return [...source.matchAll(DARK_ONLY_SURFACE_CLASS)].map((match) => `${file}: ${match[0]}`);
    });

    expect(violations).toEqual([]);
  });
});
