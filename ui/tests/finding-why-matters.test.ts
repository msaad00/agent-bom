import { describe, expect, it } from "vitest";

import { buildWhyItMatters } from "@/lib/finding-why-matters";
import type { EnrichedVuln } from "@/lib/findings-view";

function baseVuln(overrides: Partial<EnrichedVuln> = {}): EnrichedVuln {
  return {
    id: "GHSA-test",
    severity: "high",
    packages: ["pillow"],
    agents: ["cursor"],
    sources: ["demo"],
    affected_servers: ["database-server"],
    exposed_credentials: ["AWS_SECRET_ACCESS_KEY"],
    reachable_tools: ["run_shell"],
    references: [],
    advisory_sources: [],
    remediation_items: [],
    ...overrides,
  };
}

describe("buildWhyItMatters", () => {
  it("returns null when no reach, runtime, exposure, or compliance context exists", () => {
    expect(
      buildWhyItMatters(
        baseVuln({
          exposed_credentials: [],
          reachable_tools: [],
          agents: [],
        }),
      ),
    ).toBeNull();
  });

  it("summarizes reach, runtime, exposure, and compliance with proof links", () => {
    const narrative = buildWhyItMatters(
      baseVuln({
        effective_reach_band: "high",
        effective_reach_score: 82,
        graph_reachable: true,
        graph_min_hop_distance: 2,
        runtime_evidence: { state: "blocked", blocked_count: 3 },
        framework_tags: ["owasp_llm:llm06", "mitre_atlas:exfiltration"],
        phantom_tools: ["phantom-tool"],
      }),
    );

    expect(narrative).not.toBeNull();
    expect(narrative?.paragraphs.join(" ")).toMatch(/Reachability is high/);
    expect(narrative?.paragraphs.join(" ")).toMatch(/Runtime enforcement already blocked/);
    expect(narrative?.paragraphs.join(" ")).toMatch(/Blast radius spans/);
    expect(narrative?.paragraphs.join(" ")).toMatch(/compliance control tag/);
    expect(narrative?.links.map((link) => link.href)).toEqual(
      expect.arrayContaining(["/security-graph", "/traces", "/compliance"]),
    );
  });
});
