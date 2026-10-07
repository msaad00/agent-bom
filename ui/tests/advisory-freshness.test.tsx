import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AdvisoryFreshness } from "@/components/advisory-freshness";
const { getIntelSources } = vi.hoisted(() => ({ getIntelSources: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getIntelSources } }));
beforeEach(() => { getIntelSources.mockReset(); });
describe("advisory freshness", () => {
  it("keeps missing source timestamps unknown independently of scan freshness", async () => {
    getIntelSources.mockResolvedValue({ sources: [{ source_id: "osv", display_name: "OSV", enabled: true, feed_run: { last_synced: null, status: "not_synced", cap_hit: true } }] });
    render(<AdvisoryFreshness />);
    expect(await screen.findByText(/1 enabled sources/)).toBeInTheDocument();
    expect(screen.getByText(/Last sync: unknown/)).toBeInTheDocument();
    expect(screen.getByText(/partial feed/)).toBeInTheDocument();
  });
  it("does not translate a failed source request into current data", async () => {
    getIntelSources.mockRejectedValue(new Error("unavailable"));
    render(<AdvisoryFreshness />);
    expect(await screen.findByText(/source status unavailable/)).toBeInTheDocument();
    expect(screen.queryByText(/0 enabled sources/)).not.toBeInTheDocument();
  });
});
