import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { OverviewAssets } from "@/components/overview-assets";
import type { InventorySummaryResponse } from "@/lib/api";

const summary: InventorySummaryResponse = { schema_version: "inventory.summary.v1", tenant_id: "tenant-a", by_group: {}, finding_count: 0, facets: { type: {buckets: []}, source: {buckets: []}, provider: {buckets: []}, environment: {buckets: []}, severity: {buckets: []} }, facet_metadata: {basis: "whole_query", mode: "self_excluding", exact: true, scan_id: "snapshot/a b"}, completeness: {status: "complete", complete: true, sampled: false, truncated: false, returned: 126, total: 126}, scan_id: "snapshot/a b", total_assets: 126, by_type: { agent: 2, model: 40, framework: 20, server: 3, tool: 10, tool_call: 50, user: 1 } };

describe("recorded estate summary", () => {
  it("does not promote models to agents or tool calls to servers and locks drilldowns to its snapshot", () => {
    render(<OverviewAssets summary={summary} />);
    expect(screen.getByRole("link", { name: "2 Agents" })).toHaveAttribute("href", "/inventory?scan=snapshot%2Fa+b&type=agent");
    expect(screen.getByRole("link", { name: "3 Servers" })).toHaveAttribute("href", "/inventory?scan=snapshot%2Fa+b&type=server");
    expect(screen.getByRole("link", { name: "10 Tools" })).toBeVisible();
    expect(screen.queryByText(/62 Agents|63 Servers|MCP servers/)).not.toBeInTheDocument();
    expect(screen.getByText(/Coverage not established by asset counts/)).toBeVisible();
  });
  it("preserves the qualified query and never labels excluded types as empty", () => {
    render(<OverviewAssets summary={{ ...summary, count_exact: true, filters: {type: ["agent"], environment: "production", provider: "aws", source: "collector/a", search: "team one", severity: "high", min_severity: ""}, collection_coverage: {status: "unknown", reason: "Source collection has not been established"} }} />);
    const link = screen.getByRole("link", {name: "2 Agents"});
    const url = new URL(link.getAttribute("href")!, "http://localhost");
    expect(Object.fromEntries(url.searchParams)).toEqual({scan: "snapshot/a b", type: "agent", environment: "production", provider: "aws", source: "collector/a", search: "team one", severity: "high"});
    expect(screen.queryByRole("link", {name: /Servers/})).not.toBeInTheDocument();
    expect(screen.getByText("Exact within snapshot")).toBeVisible();
    expect(screen.getByText("Collection coverage: unknown")).toBeVisible();
  });
  it("shows unavailable and loading independently instead of producing zero counts", () => {
    const view = render(<OverviewAssets loading />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading recorded assets");
    view.rerender(<OverviewAssets unavailable />);
    expect(screen.getByRole("status")).toHaveTextContent("Recorded asset summary unavailable");
    expect(screen.queryByRole("link", { name: /0 Agents/ })).not.toBeInTheDocument();
  });
  it("keeps a successfully read empty snapshot distinct from unavailable", () => {
    render(<OverviewAssets summary={{...summary, total_assets: 0, by_type: {}}} />);
    expect(screen.getByRole("link", { name: "0 Agents" })).toBeVisible();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Review sources/ })).toHaveAttribute("href", "/connections");
  });
  it("qualifies nonexact records and does not turn absent types into zero", () => {
    render(<OverviewAssets summary={{...summary, count_exact: false, by_type: {agent: 2, package: 0}}} />);
    expect(screen.getByRole("link", {name: "At least 2 Agents"})).toBeVisible();
    expect(screen.getByRole("link", {name: "Servers count unavailable"})).toBeVisible();
    expect(screen.getByRole("link", {name: "Packages count unavailable"})).toBeVisible();
    expect(screen.queryByRole("link", {name: "0 Servers"})).not.toBeInTheDocument();
  });
  it("retains the requested evidence boundary after a summary failure", () => {
    render(<OverviewAssets unavailable unavailableHref="/inventory?scan=scan-a&provider=aws&min_severity=high" />);
    expect(screen.getByRole("link", {name: "Open asset inventory"})).toHaveAttribute("href", "/inventory?scan=scan-a&provider=aws&min_severity=high");
  });

});
