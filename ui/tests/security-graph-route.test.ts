import { describe, expect, it } from "vitest";

import { resolveSecurityGraphSurface } from "@/lib/security-graph-route";

describe("security graph entry routing", () => {
  it("opens the current estate canvas for an unfocused investigation entry", () => {
    expect(resolveSecurityGraphSurface(new URLSearchParams())).toBe("estate");
    expect(resolveSecurityGraphSurface(new URLSearchParams("scan=scan-123"))).toBe("estate");
  });

  it("keeps legacy focused finding links on the attack-path investigation", () => {
    for (const query of [
      "cve=CVE-2026-0042",
      "package=werkzeug",
      "agent=payments-agent",
      "node=package%3Awerkzeug",
      "finding=finding-uuid",
      "trace=trace-123",
    ]) {
      expect(resolveSecurityGraphSurface(new URLSearchParams(query))).toBe("attack-path");
    }
  });

  it("honors explicit lenses over inferred legacy focus", () => {
    expect(resolveSecurityGraphSurface(new URLSearchParams("lens=attack-path"))).toBe("attack-path");
    expect(resolveSecurityGraphSurface(new URLSearchParams("lens=estate&cve=CVE-2026-0042"))).toBe("estate");
    expect(resolveSecurityGraphSurface(new URLSearchParams("lens=lineage"))).toBe("graph");
    expect(resolveSecurityGraphSurface(new URLSearchParams("lens=mesh"))).toBe("graph");
  });
});
