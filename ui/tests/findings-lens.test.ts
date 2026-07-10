import { describe, expect, it } from "vitest";

import {
  findingsLensHint,
  findingsPageSubtitle,
  findingsQueueTitle,
  normalizeFindingsLens,
} from "@/lib/findings-lens";

describe("findings-lens", () => {
  it("normalizes trust aliases for GRC and audit entry points", () => {
    expect(normalizeFindingsLens("trust")).toBe("trust");
    expect(normalizeFindingsLens("grc")).toBe("trust");
    expect(normalizeFindingsLens("compliance")).toBe("trust");
    expect(normalizeFindingsLens("audit")).toBe("trust");
    expect(normalizeFindingsLens("ops")).toBe("ops");
    expect(normalizeFindingsLens("engineer")).toBe("ops");
  });

  it("frames the page for both engineering and GRC audiences", () => {
    expect(findingsQueueTitle("trust")).toBe("Disposition queue");
    expect(findingsQueueTitle("ops")).toBe("Findings queue");
    expect(findingsLensHint("trust")).toMatch(/GRC|audit/i);
    expect(findingsLensHint("ops")).toMatch(/Engineering/i);
    expect(findingsPageSubtitle("trust", "12 findings", "from latest.")).toMatch(/Shared with engineering/i);
    expect(findingsPageSubtitle("ops", "12 findings", "from latest.")).toMatch(/Shared with compliance/i);
  });
});
