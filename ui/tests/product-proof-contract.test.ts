import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const source = fs.readFileSync(path.join(process.cwd(), "scripts", "capture-product-proof.mjs"), "utf8");
const findingsQueue = fs.readFileSync(path.join(process.cwd(), "components", "findings-queue.tsx"), "utf8");

describe("product proof capture contract", () => {
  it("uses unmistakably fictional vulnerability identifiers", () => {
    expect(source).not.toMatch(/CVE-\d{4}-\d+/);
    expect(source).toContain("DEMO-VULN-");
    expect(source).not.toContain('source: "nvd"');
    expect(source).not.toContain("is_kev: true");
  });

  it("fails capture on HTTP, browser, visible, or version errors", () => {
    expect(source).toContain("response.ok()");
    expect(source).toContain('page.on("console"');
    expect(source).toContain('page.on("pageerror"');
    expect(source).toContain("visibleErrorPatterns");
    expect(source).toContain("RELEASE_VERSION");
  });

  it("does not present fictional identifiers as OSV advisories", () => {
    expect(findingsQueue).toContain("getOsvVulnerabilityUrl(v.id)");
    expect(findingsQueue).not.toContain("https://osv.dev/vulnerability/${v.id}");
  });
});
