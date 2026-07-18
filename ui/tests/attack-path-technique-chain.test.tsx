import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AttackPathTechniqueChain } from "@/components/attack-path-technique-chain";
import type { AttackPath } from "@/lib/graph-schema";

function basePath(overrides: Partial<AttackPath> = {}): AttackPath {
  return {
    source: "agent-1",
    target: "data-1",
    hops: ["agent-1", "identity-1", "data-1"],
    edges: ["authenticates_as", "exposed_to"],
    composite_risk: 72,
    summary: "Agent reaches a sensitive data store.",
    credential_exposure: [],
    tool_exposure: [],
    vuln_ids: [],
    ...overrides,
  };
}

describe("AttackPathTechniqueChain", () => {
  it("renders a technique badge per mapping with id, name, catalog and tactics", () => {
    const path = basePath({
      technique_mappings: [
        {
          hop_index: 0,
          technique_id: "T1078",
          technique_name: "Valid Accounts",
          catalog: "attack",
          tactics: ["Defense Evasion", "Persistence"],
          provenance: "agent authenticates_as identity",
          confidence: 0.8,
        },
        {
          hop_index: 1,
          technique_id: "AML.T0053",
          technique_name: "LLM Plugin Compromise",
          catalog: "atlas",
          tactics: ["Impact"],
          provenance: "identity exposed_to data store",
          confidence: 0.5,
        },
      ],
      mitre_technique_ids: ["AML.T0053", "T1078"],
    });

    render(<AttackPathTechniqueChain path={path} />);

    expect(screen.getByText("T1078")).toBeInTheDocument();
    expect(screen.getByText("Valid Accounts")).toBeInTheDocument();
    expect(screen.getByText("AML.T0053")).toBeInTheDocument();
    expect(screen.getByText("LLM Plugin Compromise")).toBeInTheDocument();
    // A tactic surfaces
    expect(screen.getByText(/Defense Evasion/)).toBeInTheDocument();
    // Catalog labelling distinguishes ATT&CK vs ATLAS
    expect(screen.getByText("ATLAS")).toBeInTheDocument();
  });

  it("carries the honesty framing — mapped/potential, not observed activity", () => {
    const path = basePath({
      technique_mappings: [
        {
          hop_index: 0,
          technique_id: "T1078",
          technique_name: "Valid Accounts",
          catalog: "attack",
          tactics: ["Persistence"],
          provenance: "agent authenticates_as identity",
          confidence: 0.8,
        },
      ],
    });

    render(<AttackPathTechniqueChain path={path} />);

    // Heading names it as MAPPED, not detected
    expect(screen.getByText(/Mapped ATT&CK/i)).toBeInTheDocument();
    // Explicit disclaimer that this is potential, not observed
    expect(
      screen.getByText(/not observed (attacker )?activity/i),
    ).toBeInTheDocument();
  });

  it("orders technique hops by hop_index regardless of input order", () => {
    const path = basePath({
      technique_mappings: [
        {
          hop_index: 2,
          technique_id: "T3333",
          technique_name: "Third",
          catalog: "attack",
          tactics: [],
          provenance: "",
          confidence: 0.1,
        },
        {
          hop_index: 0,
          technique_id: "T1111",
          technique_name: "First",
          catalog: "attack",
          tactics: [],
          provenance: "",
          confidence: 0.1,
        },
        {
          hop_index: 1,
          technique_id: "T2222",
          technique_name: "Second",
          catalog: "attack",
          tactics: [],
          provenance: "",
          confidence: 0.1,
        },
      ],
    });

    const { container } = render(<AttackPathTechniqueChain path={path} />);
    const list = within(container).getByTestId("technique-chain");
    const rendered = within(list)
      .getAllByTestId("technique-id")
      .map((el) => el.textContent);
    expect(rendered).toEqual(["T1111", "T2222", "T3333"]);
  });

  it("renders nothing (no crash) for a path with no mappings", () => {
    const { container: emptyArr } = render(
      <AttackPathTechniqueChain path={basePath({ technique_mappings: [] })} />,
    );
    expect(emptyArr).toBeEmptyDOMElement();

    const { container: missing } = render(
      <AttackPathTechniqueChain path={basePath()} />,
    );
    expect(missing).toBeEmptyDOMElement();
  });
});
