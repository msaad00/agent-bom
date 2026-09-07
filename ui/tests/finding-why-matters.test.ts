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

  it("does not infer reachability from severity or exploitation from runtime activity", () => {
    const narrative = buildWhyItMatters(baseVuln({ runtime_evidence: { state: "observed", observed_count: 2 } }));
    expect(narrative?.headline).not.toMatch(/reachable/i);
    expect(narrative?.paragraphs.join(" ")).not.toMatch(/exploitability is not theoretical|live paths|confirmed tool/);
    expect(narrative?.paragraphs.join(" ")).toMatch(/does not prove exploitation/);
  });

  it("does not treat a blocked invocation as completed remediation", () => {
    const narrative = buildWhyItMatters(baseVuln({ runtime_evidence: { state: "blocked", blocked_count: 3 } }));
    expect(narrative?.paragraphs.join(" ")).toMatch(/remediation still needs verification/);
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
    expect(narrative?.paragraphs.join(" ")).toMatch(/Reported reachability is high/);
    expect(narrative?.paragraphs.join(" ")).toMatch(/Runtime enforcement recorded blocked/);
    expect(narrative?.paragraphs.join(" ")).toMatch(/Reported scope includes/);
    // Compliance mapping is now scannable chip data, not a run-on paragraph.
    expect(narrative?.complianceTags).toEqual(["owasp_llm:llm06", "mitre_atlas:exfiltration"]);
    expect(narrative?.links.map((link) => link.href)).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^\/security-graph/),
        "/traces",
        "/compliance",
      ]),
    );
  });
});
