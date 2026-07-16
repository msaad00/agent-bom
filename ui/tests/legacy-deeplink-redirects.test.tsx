import { describe, expect, it, vi, beforeEach } from "vitest";

const { redirectMock } = vi.hoisted(() => ({ redirectMock: vi.fn() }));

vi.mock("next/navigation", () => ({ redirect: redirectMock }));

import ThreatIntelRedirect from "@/app/threat-intel/page";
import ReportsRedirect from "@/app/reports/page";

// Note: `/inventory` no longer redirects — it is now the unified Asset Inventory
// section landing (see tests/inventory-view.test.tsx). The AI BOM surface stays
// reachable via the AI inventory nav group and the Inventory "AI agents" page.
describe("legacy deep-link redirects", () => {
  beforeEach(() => {
    redirectMock.mockClear();
  });

  it("routes /threat-intel to the Integrations intel tab", () => {
    ThreatIntelRedirect();
    expect(redirectMock).toHaveBeenCalledWith("/integrations?tab=intel");
  });

  it("routes /reports to the Integrations reports tab", () => {
    ReportsRedirect();
    expect(redirectMock).toHaveBeenCalledWith("/integrations?tab=reports");
  });
});
