import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphHopEvidenceInspector } from "@/components/graph-hop-evidence-inspector";
import type { GraphHopEvidence } from "@/lib/graph-schema";

const hops = ["Agent", "Tool", "Identity", "Data"].map((label, index) => ({ id: `node:${index}`, label }));
function receipt(index: number, overrides: Partial<GraphHopEvidence> = {}): GraphHopEvidence {
  return {
    source_node_id: `node:${index}`, target_node_id: `node:${index + 1}`, relationship: "uses",
    source_snapshot_ids: ["scan:synthetic"], relationship_provenance: "recorded", correlation_identity_status: "current",
    evidence_tier: "static_evidence", confidence: 1, freshness: "fresh", runtime_observed_state: "not_observed",
    direction: "directed", traversable: true, complete: true, truncated: false, ...overrides,
  };
}

describe("GraphHopEvidenceInspector", () => {
  it("finds native privileges without changing hop identity or inferring permission", () => {
    render(<GraphHopEvidenceInspector hops={hops} receipts={[receipt(0), receipt(1, {authority: {
      status: "recorded", decisions: [], derivation: null, reason_codes: [], native_grants: [
        {source: "snowflake-objects", privilege: "INSERT", account: "account-a", role: "ANALYST", object_fqn: "DB.PUBLIC.ORDERS", object_type: "table"},
      ],
    }}), receipt(2)]} />);
    fireEvent.change(screen.getByRole("textbox", {name: "Filter hop evidence"}), {target: {value: "INSERT"}});
    fireEvent.click(screen.getByRole("button", {name: /2\. Tool/}));
    expect(screen.getByText("INSERT · Native grant")).toBeInTheDocument();
    expect(screen.queryByRole("button", {name: /1\. Agent/})).not.toBeInTheDocument();
    expect(screen.getByText("DB.PUBLIC.ORDERS")).toBeInTheDocument();
  });
  it("separates blocked, failed, and unknown downstream outcomes from runtime observation", () => {
    render(<GraphHopEvidenceInspector hops={hops} receipts={[
      receipt(0, {runtime_observed_state: "observed", runtime_outcome: "blocked"}),
      receipt(1, {runtime_observed_state: "observed", runtime_outcome: "failed"}), receipt(2, {runtime_observed_state: "observed"}),
    ]} />);
    expect(screen.getByText("Blocked attempt")).toBeInTheDocument();
    expect(screen.getByText("Failed outcome")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", {name: /1\. Agent/}));
    expect(screen.getByText(/cannot establish a successful downstream action/)).toBeInTheDocument();
    expect(screen.getByText("Downstream outcome").nextElementSibling).toHaveTextContent("blocked");
    fireEvent.click(screen.getByRole("button", {name: /3\. Identity/}));
    expect(screen.getByText("Downstream outcome").nextElementSibling).toHaveTextContent("unknown");
    expect(screen.getByText("Runtime observation").nextElementSibling).toHaveTextContent("observed");
    expect(screen.getAllByRole("button", {expanded: true})).toHaveLength(1);
  });

  it("retains missing positions and rejects mismatched receipt endpoints", () => {
    render(<GraphHopEvidenceInspector hops={hops} receipts={[receipt(1)]} />);
    expect(screen.getAllByText("Receipt unavailable")).toHaveLength(3);
    fireEvent.click(screen.getByRole("button", {name: /1\. Agent/}));
    expect(screen.getByText(/Collect source evidence/)).toBeInTheDocument();
    expect(screen.queryByText("scan:synthetic")).not.toBeInTheDocument();
  });

  it("renders malformed legacy metadata as unknown instead of crashing", () => {
    const malformed = {source_node_id: "node:0", target_node_id: "node:1", source_snapshot_ids: [{untrusted: true}], reason_codes: "malformed"};
    render(<GraphHopEvidenceInspector hops={hops.slice(0, 2)} receipts={[malformed as unknown as GraphHopEvidence]} />);
    fireEvent.click(screen.getByRole("button", {name: /1\. Agent/}));
    expect(screen.getByText("Evidence incomplete")).toBeInTheDocument();
    expect(screen.getByText("Not recorded")).toBeInTheDocument();
  });

  it.each([undefined, "false"])("does not infer traversal from legacy value %s", (traversable) => {
    const legacy = { ...receipt(0), traversable } as unknown as GraphHopEvidence;
    render(<GraphHopEvidenceInspector hops={hops.slice(0, 2)} receipts={[legacy]} />);
    fireEvent.click(screen.getByRole("button", { name: /1\. Agent/ }));
    expect(screen.getByText("Traversal").nextElementSibling).toHaveTextContent(/^unknown$/);
  });

  it("limits rendered rows and keeps original hop numbers when filtering a long path", () => {
    const longHops = Array.from({length: 1001}, (_, index) => ({id: `node:${index}`, label: `Asset ${index}`}));
    render(<GraphHopEvidenceInspector hops={longHops} />);
    const list = screen.getByRole("list");
    expect(within(list).getAllByRole("listitem")).toHaveLength(8);
    fireEvent.click(screen.getByRole("button", {name: "Next hops"}));
    expect(screen.getByRole("button", {name: /9\. Asset 8 → Asset 9/})).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", {name: "Filter hop evidence"}), {target: {value: "Asset 999"}});
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByRole("button", {name: /1000\. Asset 999 → Asset 1000/})).toBeInTheDocument();
    fireEvent.change(screen.getByRole("textbox", {name: "Filter hop evidence"}), {target: {value: "no-such-asset"}});
    expect(screen.getByText("No hops match this filter. The path is unchanged.")).toBeInTheDocument();
  });

  it("keeps untrusted labels and snapshot locators as inert text", () => {
    const label = '<img src=x onerror="fetch(\"https://invalid.example\")">';
    const {container} = render(<GraphHopEvidenceInspector hops={[{id: "node:0", label}, hops[1]!]} receipts={[receipt(0, {source_snapshot_ids: ["javascript:alert(1)"]})]} />);
    fireEvent.click(screen.getByRole("button"));
    expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument();
    expect(container.querySelectorAll("a,img,iframe,script")).toHaveLength(0);
    expect(screen.getByRole("button")).toHaveTextContent(label);
  });

  it("explains an empty path without implying clean coverage", () => {
    render(<GraphHopEvidenceInspector hops={[]} />);
    expect(screen.getByText("This path has no relationships to inspect.")).toBeInTheDocument();
  });
});
