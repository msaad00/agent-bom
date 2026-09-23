import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AgentInvestigationQuestions } from "@/components/agent-investigation-questions";
import type { ExposurePath } from "@/lib/exposure-path";

const agent = { id: "agent:a", label: "agent/A", rawLabel: "agent/A", entityType: "agent", role: "agent" as const };
const target = { id: "vuln:v", label: "CVE-fixture", role: "finding" as const };
const path: ExposurePath = {
  id: "p", label: "fixture", riskScore: 1, severity: "high", source: agent, target,
  hops: [agent, target], nodeIds: [agent.id, target.id], relationships: [], edgeIds: [], findings: [target.label],
  affectedAgents: [agent.label], affectedServers: [], reachableTools: [], exposedCredentials: [],
};

describe("Agent investigation questions", () => {
  it("keeps missing local exploitability and prerequisites unknown", () => {
    render(<AgentInvestigationQuestions path={path} onConnections={vi.fn()} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "CVE conditions" }));
    expect(screen.getByText(/Local exploitability: not assessed/)).toBeInTheDocument();
    expect(screen.getAllByText("Not recorded")).toHaveLength(4);
  });
  it("shows recorded advisory prerequisites without upgrading exploitability", () => {
    render(<AgentInvestigationQuestions path={{ ...path, evidence: { privilegesRequired: "high", userInteraction: "required", attackVector: "network", attackComplexity: "high" } }} onConnections={vi.fn()} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "CVE conditions" }));
    expect(screen.getByText("required")).toBeInTheDocument();
    expect(screen.getByText(/Local exploitability: not assessed/)).toBeInTheDocument();
  });
  it("requires an explicit scenario assumption and keeps unavailable impact unknown", () => {
    render(<AgentInvestigationQuestions path={path} onConnections={vi.fn()} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Assume compromise" }));
    expect(screen.queryByText("Scenario assumption only.")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByText("Scenario assumption only.")).toBeInTheDocument();
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Potential impact" }));
    expect(screen.getByText(/No downstream data asset/)).toBeInTheDocument();
  });
  it("rejects a runtime receipt belonging to another hop and preserves agent URL identity", () => {
    const other = { source_node_id: "other", target_node_id: target.id, runtime_observed_state: "observed" };
    render(<AgentInvestigationQuestions path={{ ...path, hopEvidence: [other as NonNullable<ExposurePath["hopEvidence"]>[number]] }} scanId="scan/a" onConnections={vi.fn()} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Recorded activity" }));
    expect(screen.getByText(/No runtime observation is attached/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Recorded activity for agent/A" })).toHaveAttribute("href", "/traces?agent=agent%2FA&scan=scan%2Fa");
  });
  it("uses recorded agent identity rather than a formatted display label", () => {
    render(<AgentInvestigationQuestions path={{ ...path, hops: [{ ...agent, label: "Agent A (display)" }, target] }} onConnections={vi.fn()} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Recorded activity" }));
    expect(screen.getByRole("link", { name: "Recorded activity for agent/A" })).toHaveAttribute("href", "/traces?agent=agent%2FA");
  });
  it("does not assign identity nodes as compromised agents and includes canonical resources", () => {
    const identity = { id: "user:a", label: "Alice", role: "agent" as const, entityType: "user" };
    const resource = { id: "data:a", label: "Customer records", role: "unknown" as const, entityType: "data_store" };
    render(<AgentInvestigationQuestions path={{ ...path, hops: [identity, resource] }} onConnections={vi.fn()} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Assume compromise" }));
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.getByText(/No canonical agent/)).toBeInTheDocument();
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Potential impact" }));
    expect(screen.getByText("Customer records")).toBeInTheDocument();
    expect(screen.queryByText(/No downstream/)).not.toBeInTheDocument();
  });
  it("opens the existing bounded connections explorer", () => {
    const open = vi.fn();
    render(<AgentInvestigationQuestions path={path} onConnections={open} />);
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Reach & connections" }));
    if (!screen.getByText("Investigate this path").parentElement?.hasAttribute("open")) fireEvent.click(screen.getByText("Investigate this path"));
    fireEvent.click(screen.getByRole("button", { name: "Explore incoming and outgoing connections" }));
    expect(open).toHaveBeenCalledOnce();
  });
});
