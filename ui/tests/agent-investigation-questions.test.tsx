import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AgentInvestigationQuestions } from "@/components/agent-investigation-questions";
import type { ExposurePath } from "@/lib/exposure-path";

const agent = { id: "agent:a", label: "agent/A", role: "agent" as const };
const target = { id: "vuln:v", label: "CVE-fixture", role: "finding" as const };
const path: ExposurePath = {
  id: "p", label: "fixture", riskScore: 1, severity: "high", source: agent, target,
  hops: [agent, target], nodeIds: [agent.id, target.id], relationships: [], edgeIds: [], findings: [target.label],
  affectedAgents: [agent.label], affectedServers: [], reachableTools: [], exposedCredentials: [],
};

describe("Agent investigation questions", () => {
  it("keeps missing local exploitability and prerequisites unknown", () => {
    render(<AgentInvestigationQuestions path={path} onConnections={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "CVE conditions" }));
    expect(screen.getByText(/Local exploitability: not assessed/)).toBeInTheDocument();
    expect(screen.getAllByText("Not recorded")).toHaveLength(4);
  });
  it("shows recorded advisory prerequisites without upgrading exploitability", () => {
    render(<AgentInvestigationQuestions path={{ ...path, evidence: { privilegesRequired: "high", userInteraction: "required", attackVector: "network", attackComplexity: "high" } }} onConnections={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "CVE conditions" }));
    expect(screen.getByText("required")).toBeInTheDocument();
    expect(screen.getByText(/Local exploitability: not assessed/)).toBeInTheDocument();
  });
  it("requires an explicit scenario assumption and keeps unavailable impact unknown", () => {
    render(<AgentInvestigationQuestions path={path} onConnections={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Assume compromise" }));
    expect(screen.queryByText("Scenario assumption only.")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByText("Scenario assumption only.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Potential impact" }));
    expect(screen.getByText(/No downstream data asset/)).toBeInTheDocument();
  });
  it("rejects a runtime receipt belonging to another hop and preserves agent URL identity", () => {
    const other = { source_node_id: "other", target_node_id: target.id, runtime_observed_state: "observed" };
    render(<AgentInvestigationQuestions path={{ ...path, hopEvidence: [other as NonNullable<ExposurePath["hopEvidence"]>[number]] }} scanId="scan/a" onConnections={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Recorded activity" }));
    expect(screen.getByText(/No runtime observation is attached/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Recorded activity for agent/A" })).toHaveAttribute("href", "/traces?agent=agent%2FA&scan=scan%2Fa");
  });
  it("opens the existing bounded connections explorer", () => {
    const open = vi.fn();
    render(<AgentInvestigationQuestions path={path} onConnections={open} />);
    fireEvent.click(screen.getByRole("button", { name: "Reach & connections" }));
    fireEvent.click(screen.getByRole("button", { name: "Explore incoming and outgoing connections" }));
    expect(open).toHaveBeenCalledOnce();
  });
});
