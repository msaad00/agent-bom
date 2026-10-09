import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const UI_ROOT = process.cwd();
const SCAN_DIRS = ["app", "components", "lib", "hooks"];
// `agent-bom api` is a hidden legacy alias; `agent-bom serve` (or
// `serve --no-ui` for REST only) is the supported way to start the backend.
const RETIRED_COMMAND = /agent-bom api\b/;

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

describe("retired CLI command guard", () => {
  it("never tells users to run the retired `agent-bom api` command", () => {
    const offenders = SCAN_DIRS.flatMap((dir) => walk(path.join(UI_ROOT, dir)))
      .filter((file) => RETIRED_COMMAND.test(readFileSync(file, "utf8")))
      .map((file) => path.relative(UI_ROOT, file));
    expect(offenders).toEqual([]);
  });
});
