import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const GUARDED_GRAPH_SURFACES = [
  "components/graph-chrome.tsx",
  "components/lineage-filter.tsx",
] as const;

const DARK_ONLY_SURFACE_CLASS =
  /\b(?:bg|border)-zinc-(?:700|800|900|950)(?:\/\d+)?\b|\btext-zinc-(?:100|200|300|400|500|600)(?:\/\d+)?\b|\b(?:bg-black|text-white|shadow-black)(?:\/\d+)?\b/g;

// Any Tailwind zinc-* color utility (bg/text/border/ring/divide/etc.), with an
// optional variant chain, ! important, and /opacity suffix. Light theme is only
// legible when every surface/label uses a semantic token from globals.css, so
// the whole UI tree must be free of hardcoded zinc utilities (#3966).
const ZINC_UTILITY =
  /(?:^|[\s"'`([{])(?:[\w.&>[\]-]+:)*!?(?:bg|text|border|divide|ring-offset|ring|placeholder|outline|fill|stroke|from|via|to)-zinc-\d{2,3}(?:\/\d+)?/g;

const UI_ROOT = process.cwd();
const SCAN_DIRS = ["app", "components", "lib", "hooks"];

function walk(dir: string): string[] {
  let out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === ".next") continue;
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      out = out.concat(walk(full));
    } else if (/\.(tsx?|jsx?)$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

describe("light theme token guard", () => {
  it("keeps shared graph chrome and filters on theme tokens instead of dark-only panels", () => {
    const violations = GUARDED_GRAPH_SURFACES.flatMap((file) => {
      const source = readFileSync(path.join(UI_ROOT, file), "utf8");
      return [...source.matchAll(DARK_ONLY_SURFACE_CLASS)].map((match) => `${file}: ${match[0]}`);
    });

    expect(violations).toEqual([]);
  });

  it("has no hardcoded zinc-* Tailwind utilities anywhere in the UI source", () => {
    const violations: string[] = [];
    for (const dir of SCAN_DIRS) {
      const base = path.join(UI_ROOT, dir);
      let files: string[];
      try {
        files = walk(base);
      } catch {
        continue; // dir may not exist
      }
      for (const file of files) {
        const source = readFileSync(file, "utf8");
        for (const match of source.matchAll(ZINC_UTILITY)) {
          violations.push(`${path.relative(UI_ROOT, file)}: ${match[0].trim()}`);
        }
      }
    }

    expect(violations).toEqual([]);
  });
});
