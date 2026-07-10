import { describe, expect, it } from "vitest";

import { frameworkLogoMeta, normalizeFrameworkLogoId } from "@/lib/framework-logos";

describe("frameworkLogoMeta", () => {
  it("resolves canonical framework ids to distinct color tiles", () => {
    expect(frameworkLogoMeta("owasp-llm")?.src).toContain("/logos/frameworks/owasp.svg");
    expect(frameworkLogoMeta("atlas")?.src).toContain("mitre-atlas.svg");
    expect(frameworkLogoMeta("nist-ai-rmf")?.src).toContain("nist-ai-rmf.svg");
    expect(frameworkLogoMeta("nist-csf")?.src).toContain("nist-csf.svg");
    expect(frameworkLogoMeta("eu-ai-act")?.src).toContain("eu-ai-act.svg");
    expect(frameworkLogoMeta("soc2")?.src).toContain("soc2.svg");
    expect(frameworkLogoMeta("cmmc")?.src).toContain("cmmc.svg");
    expect(frameworkLogoMeta("atlas")?.src).not.toEqual(frameworkLogoMeta("nist-ai-rmf")?.src);
    expect(frameworkLogoMeta("nist-csf")?.monogram).toBe("CS");
  });

  it("normalizes labels and aliases", () => {
    expect(normalizeFrameworkLogoId("OWASP MCP Top 10")).toBe("owasp-mcp");
    expect(normalizeFrameworkLogoId("MITRE ATLAS")).toBe("atlas");
  });

  it("keeps monogram metadata as image-load fallback", () => {
    const meta = frameworkLogoMeta("soc2");
    expect(meta?.monogram).toBe("S2");
    expect(meta?.src).toContain("soc2.svg");
  });
});
