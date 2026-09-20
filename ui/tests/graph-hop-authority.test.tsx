import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphHopAuthority } from "@/components/graph-hop-authority";
import type { HopAuthorityEvidence } from "@/lib/graph-schema";

const decision = (i: number): HopAuthorityEvidence["decisions"][number] => ({
  source: "authorization-evidence", provider: "gcp", decision: "allow", action: `objects.read:${i}`,
  principal_id: "principal:reader", resource: "data:example", observed_at: null, binding_ids: [`grant:${i}`],
});
describe("GraphHopAuthority", () => {
  it("paginates coupled action receipts and distinguishes historical permission from execution", () => {
    render(<GraphHopAuthority evidence={{ status: "partial", decisions: Array.from({length: 9}, (_, i) => decision(i)), derivation: null, reason_codes: ["authorization_receipt_limit"] }} />);
    expect(screen.getByText(/Snapshot evidence, not a current permission check/)).toBeInTheDocument();
    expect(screen.getByText(/Partial evidence/)).toBeInTheDocument();
    expect(screen.getAllByText(/^objects.read:/)).toHaveLength(4);
    fireEvent.click(screen.getByRole("button", {name: "Next receipts"}));
    expect(screen.getByText("objects.read:4 · allow")).toBeInTheDocument();
    expect(screen.getByText("grant:4")).toBeInTheDocument();
    expect(screen.queryByText("grant:0")).not.toBeInTheDocument();
    expect(screen.getAllByText("Not recorded")).toHaveLength(4);
  });
  it("retains ordered source witnesses without inventing an action", () => {
    render(<GraphHopAuthority evidence={{ status: "recorded", decisions: [], reason_codes: [], derivation: {
      basis: "recorded_graph_connections", source_scan_id: "scan:source", path_selection: "one_shortest_path_per_grant_and_access", truncated: false,
      paths: [{access: "group", grant_principal_id: "group:reader", grant_edge_id: "edge:grant", source_edge_ids: ["edge:member", "edge:grant"]}],
    } }} />);
    expect(screen.getByText(/Action scope is not inferred/)).toBeInTheDocument();
    expect(screen.getByText("edge:member")).toBeInTheDocument();
    expect(screen.getByText(/Source snapshot: scan:source/)).toBeInTheDocument();
    expect(screen.queryByText(/objects.read/)).not.toBeInTheDocument();
  });
  it("renders untrusted fields as text and handles malformed legacy arrays", () => {
    const {container, rerender} = render(<GraphHopAuthority evidence={{status: "recorded", decisions: [{...decision(0), action: "<script>alert(1)</script>"}], derivation: null, reason_codes: []}} />);
    expect(container.querySelectorAll("script,a,img,iframe")).toHaveLength(0);
    expect(screen.getByText("<script>alert(1)</script> · allow")).toBeInTheDocument();
    rerender(<GraphHopAuthority evidence={{decisions: "bad", derivation: {paths: [null]}, reason_codes: "bad"} as unknown as HopAuthorityEvidence} />);
    expect(screen.getByText("No valid authority receipts in this projection.")).toBeInTheDocument();
  });
});
