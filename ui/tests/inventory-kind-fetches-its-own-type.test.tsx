/**
 * An asset-type page must ask for its own asset type.
 *
 * `/inventory` advertises 93 AI agents, 211 MCP servers and 258 container
 * images. Clicking any of those three cards landed on:
 *
 *     "No ai agents discovered yet — Run a scan or connect an account"
 *
 * with every request returning 200 on a healthy API and the estate fully
 * populated. **562 advertised assets were unreachable**, and the empty state
 * told the user to run a scan they had already run.
 *
 * The mechanism is the same split this release has been closing everywhere: the
 * card COUNT comes from `stats.node_types`, computed over the whole snapshot,
 * while the ROWS come from `api.getGraph({ limit, offset: 0 })` — a *ranked*
 * page of 1,073 nodes out of 6,802, dominated by misconfigurations. Agents,
 * servers and containers rank below the cut, so the page had genuinely zero of
 * them to show.
 *
 * `/v1/graph` has accepted an `entity_types` filter the whole time, and
 * `api.getGraph` has accepted `entityTypes` the whole time. Neither was wired
 * up. So the fix is not a new capability — it is asking the question the page
 * actually means: *give me this kind*, not *give me the top of the estate and
 * hope my kind is in it*.
 */

import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { InventoryProvider } from "@/lib/inventory-context";
import { ASSET_KIND_BY_ID } from "@/lib/inventory";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, getGraph: vi.fn() } };
});

/** A ranked page shaped like the real one: misconfigurations only. */
function rankedPageWithoutAgents() {
  const nodes = Array.from({ length: 40 }, (_unused, index) => ({
    id: `misconfig:${index}`,
    entity_type: "misconfiguration",
    label: `CIS finding ${index}`,
    severity: "high",
    attributes: {},
    compliance_tags: [],
    data_sources: ["scan"],
  }));
  return {
    scan_id: "s1",
    tenant_id: "default",
    created_at: "2026-08-10T00:00:00Z",
    nodes,
    edges: [],
    attack_paths: [],
    interaction_risks: [],
    // The counts the cards render — the estate genuinely holds 93 agents.
    stats: { total_nodes: 6802, total_edges: 22993, node_types: { misconfiguration: 1581, agent: 93 } },
    pagination: { total: 6802, offset: 0, limit: 40, has_more: true },
  };
}

/** The same estate, asked the right question: only agent nodes. */
function agentOnlyPage() {
  const nodes = Array.from({ length: 5 }, (_unused, index) => ({
    id: `agent:${index}`,
    entity_type: "agent",
    label: `agent-${index}`,
    severity: "none",
    attributes: {},
    compliance_tags: [],
    data_sources: ["scan"],
  }));
  return { ...rankedPageWithoutAgents(), nodes, pagination: { total: 93, offset: 0, limit: 40, has_more: true } };
}

beforeEach(() => {
  vi.mocked(api.getGraph).mockReset();
});

describe("an asset-type page asks for its own type", () => {
  it("requests the kind's entity types rather than a global ranked page", async () => {
    vi.mocked(api.getGraph).mockResolvedValue(agentOnlyPage() as never);

    render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.agents.entityTypes}>
        <div />
      </InventoryProvider>,
    );

    await waitFor(() => expect(api.getGraph).toHaveBeenCalled());
    const call = vi.mocked(api.getGraph).mock.calls[0]?.[0];
    expect(call?.entityTypes).toEqual(ASSET_KIND_BY_ID.agents.entityTypes);
  });

  it("still fetches unfiltered when no kind is scoped (the index page)", async () => {
    vi.mocked(api.getGraph).mockResolvedValue(rankedPageWithoutAgents() as never);

    render(
      <InventoryProvider>
        <div />
      </InventoryProvider>,
    );

    await waitFor(() => expect(api.getGraph).toHaveBeenCalled());
    expect(vi.mocked(api.getGraph).mock.calls[0]?.[0]?.entityTypes).toBeUndefined();
  });

  it("renders the kind's rows instead of an empty state", async () => {
    vi.mocked(api.getGraph).mockResolvedValue(agentOnlyPage() as never);
    const { AssetInventoryView } = await import("@/components/inventory/asset-inventory-view");

    render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.agents.entityTypes}>
        <AssetInventoryView kind="agents" />
      </InventoryProvider>,
    );

    await waitFor(() => expect(screen.queryByText(/discovered yet/i)).toBeNull());
    expect(screen.getByText("agent-0")).toBeInTheDocument();
  });

  it("refetches when the scoped kind changes", async () => {
    vi.mocked(api.getGraph).mockResolvedValue(agentOnlyPage() as never);

    const { rerender } = render(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.agents.entityTypes}>
        <div />
      </InventoryProvider>,
    );
    await waitFor(() => expect(api.getGraph).toHaveBeenCalledTimes(1));

    rerender(
      <InventoryProvider entityTypes={ASSET_KIND_BY_ID.containers.entityTypes}>
        <div />
      </InventoryProvider>,
    );
    await waitFor(() => expect(api.getGraph).toHaveBeenCalledTimes(2));
    expect(vi.mocked(api.getGraph).mock.calls[1]?.[0]?.entityTypes).toEqual(
      ASSET_KIND_BY_ID.containers.entityTypes,
    );
  });
});
