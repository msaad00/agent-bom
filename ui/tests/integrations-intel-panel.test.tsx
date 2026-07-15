import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { IntelPanel } from "@/components/integrations/intel-panel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getIntelSources: vi.fn(),
    getIntelAdvisory: vi.fn(),
    matchIntelPackages: vi.fn(),
    getIntelDailyBrief: vi.fn(),
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock, formatDate: (s: string) => s }));

const SOURCE = {
  source_id: "nvd",
  display_name: "NVD",
  tier: "authoritative",
  kind: "cve",
  validation_status: "validated",
  support_status: "supported",
  enabled: true,
  owner: "nist",
  description: "",
  feed_run: {
    sync_meta_source: "nvd",
    last_synced: "2026-07-14T00:00:00Z",
    record_count: 4200,
    status: "synced",
    validation_status: "validated",
    parse_errors: 0,
    validation_failures: 0,
    cap_hit: false,
  },
};

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  apiMock.getIntelSources.mockResolvedValue({ schema_version: "v1", sources: [SOURCE], count: 1 });
});

describe("IntelPanel", () => {
  it("renders sources and filters by search", async () => {
    render(<IntelPanel />);
    expect(await screen.findByText("NVD")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("intel-source-search"), { target: { value: "zzz-nomatch" } });
    await waitFor(() => expect(screen.queryByText("NVD")).not.toBeInTheDocument());
  });

  it("looks up an advisory by id", async () => {
    apiMock.getIntelAdvisory.mockResolvedValue({
      schema_version: "v1",
      found: true,
      query: "CVE-2024-3094",
      advisory: {
        id: "CVE-2024-3094",
        summary: "backdoor",
        severity: "critical",
        cvss_score: 10,
        cvss_vector: null,
        fixed_version: "5.6.2",
        source: "nvd",
        published_at: "2026-01-01T00:00:00Z",
        modified_at: null,
        epss_probability: 0.5,
        epss_percentile: 0.9,
        is_kev: true,
        kev_date_added: "2026-01-02",
        affected: [{}],
        canonical_ids: { cves: [], ghsas: [], osv: [], cwes: [] },
        evidence_links: [],
      },
    });
    render(<IntelPanel />);
    await screen.findByText("NVD");
    fireEvent.change(screen.getByTestId("intel-advisory-input"), { target: { value: "CVE-2024-3094" } });
    fireEvent.click(screen.getByTestId("intel-advisory-submit"));
    await waitFor(() => expect(apiMock.getIntelAdvisory).toHaveBeenCalledWith("CVE-2024-3094"));
    const result = await screen.findByTestId("intel-advisory-result");
    expect(result).toHaveTextContent("CVE-2024-3094");
    expect(result).toHaveTextContent(/KEV/);
  });

  it("matches a package against advisory intel", async () => {
    apiMock.matchIntelPackages.mockResolvedValue({
      schema_version: "v1",
      submitted: 1,
      matched_packages: 1,
      match_count: 3,
      matches: [],
    });
    render(<IntelPanel />);
    await screen.findByText("NVD");
    fireEvent.change(screen.getByTestId("intel-match-ecosystem"), { target: { value: "npm" } });
    fireEvent.change(screen.getByTestId("intel-match-name"), { target: { value: "left-pad" } });
    fireEvent.click(screen.getByTestId("intel-match-submit"));
    await waitFor(() =>
      expect(apiMock.matchIntelPackages).toHaveBeenCalledWith([
        { ecosystem: "npm", name: "left-pad", version: undefined },
      ]),
    );
    expect(await screen.findByTestId("intel-match-result")).toHaveTextContent("3 advisor");
  });

  it("generates a daily brief", async () => {
    apiMock.getIntelDailyBrief.mockResolvedValue({
      schema_version: "v1",
      generated_at: "2026-07-14T00:00:00Z",
      inputs: {},
      sections: {
        kev_last_24h: [{}, {}],
        high_epss_inventory: [],
        vendor_advisories: [],
        ioc_telemetry_hits: [],
        campaign_matches: [],
        ransomware_sector_matches: [],
      },
      limitations: ["telemetry needed"],
    });
    render(<IntelPanel />);
    await screen.findByText("NVD");
    fireEvent.click(screen.getByTestId("intel-brief-submit"));
    await waitFor(() => expect(apiMock.getIntelDailyBrief).toHaveBeenCalled());
    expect(await screen.findByTestId("intel-brief-result")).toHaveTextContent("KEV in last 24h");
  });
});
