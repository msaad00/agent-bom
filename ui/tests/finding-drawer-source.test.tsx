import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { FindingDrawer } from "@/components/finding-drawer";
import type { EnrichedVuln } from "@/lib/findings-view";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ hasCapability: () => false }) }));

const source = "sbom:/private/tmp/reference/model.cdx.json";
const base: EnrichedVuln = {
  id: "CVE-2020-14343", severity: "high", packages: ["pyyaml"], agents: [source],
  affected_servers: [source], sources: [], exposed_credentials: [], reachable_tools: [],
  references: [], advisory_sources: [], remediation_items: [],
};

it("presents SBOM artifacts as sources across overview and evidence without losing their paths", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={base} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText("SBOM evidence; workload not identified")).toBeVisible();
  expect(screen.getByText("SBOM source: model.cdx.json")).toBeVisible();
  expect(screen.queryByText(/1 agent|1 MCP server/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("SBOM sources")).toBeVisible();
  expect(screen.getByText(source)).toBeVisible();
  expect(screen.queryByText("Agents")).not.toBeInTheDocument();
  expect(screen.queryByText("MCP servers")).not.toBeInTheDocument();
  expect(screen.queryByText(/1 agent surface/)).not.toBeInTheDocument();
  expect(base.agents).toEqual([source]);
  expect(base.affected_servers).toEqual([source]);
});

it("keeps real agents and servers alongside separately labeled SBOM evidence", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={{ ...base, agents: [source, "cursor"], affected_servers: [source, "api-mcp"] }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  expect(screen.getByText("1 agent · 1 MCP server")).toBeVisible();
  expect(screen.queryByText(/workload not identified/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("Agents")).toBeVisible();
  expect(screen.getByText("MCP servers")).toBeVisible();
  expect(screen.getByText(source)).toBeVisible();
  expect(screen.getByText(/1 agent surface/)).toBeVisible();
});


it("renders structured CWEs without mining summary prose", async () => {
  const user = userEvent.setup();
  render(<FindingDrawer vuln={{ ...base, cwe_ids: ["CWE-79", "CWE-79", "CWE-89"], summary: "An unrelated CWE-999 label in advisory prose" }} triage={undefined} triageBusy={false} onTriageDecision={vi.fn()} onClose={vi.fn()} />);
  await user.click(screen.getByRole("tab", { name: "Evidence" }));
  expect(screen.getByText("Weaknesses")).toBeVisible();
  expect(screen.getAllByText("CWE-79")).toHaveLength(1);
  expect(screen.getByText("CWE-89")).toBeVisible();
  expect(screen.queryByText("CWE-999", { exact: true })).not.toBeInTheDocument();
});
