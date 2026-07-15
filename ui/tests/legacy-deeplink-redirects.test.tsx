import { describe, expect, it, vi, beforeEach } from "vitest";

const { redirectMock } = vi.hoisted(() => ({ redirectMock: vi.fn() }));

vi.mock("next/navigation", () => ({ redirect: redirectMock }));

import InventoryRedirect from "@/app/inventory/page";
import ThreatIntelRedirect from "@/app/threat-intel/page";
import ReportsRedirect from "@/app/reports/page";

describe("legacy deep-link redirects", () => {
  beforeEach(() => {
    redirectMock.mockClear();
  });

  it("routes /inventory to the AI BOM surface", () => {
    InventoryRedirect();
    expect(redirectMock).toHaveBeenCalledWith("/manifest");
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
