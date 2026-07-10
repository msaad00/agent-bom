import { describe, expect, it } from "vitest";

import { frameworkLogoMeta, normalizeFrameworkLogoId } from "@/lib/framework-logos";

describe("frameworkLogoMeta", () => {
  it("resolves canonical framework ids", () => {
    expect(frameworkLogoMeta("owasp-llm")?.src).toBe("/logos/frameworks/owasp.svg");
    expect(frameworkLogoMeta("nist-csf")?.monogram).toBe("CS");
  });

  it("normalizes labels and aliases", () => {
    expect(normalizeFrameworkLogoId("OWASP MCP Top 10")).toBe("owasp-mcp");
    expect(normalizeFrameworkLogoId("MITRE ATLAS")).toBe("atlas");
  });

  it("uses monogram-only metadata for frameworks without shipped marks", () => {
    const meta = frameworkLogoMeta("soc2");
    expect(meta?.src).toBeNull();
    expect(meta?.monogram).toBe("S2");
  });
});
