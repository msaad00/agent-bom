import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphHopAuthority } from "@/components/graph-hop-authority";
import type { HopAuthorityEvidence } from "@/lib/graph-schema";

const decision = (i: number): HopAuthorityEvidence["decisions"][number] => ({
  source: "authorization-evidence", provider: "gcp", decision: "allow", action: `objects.read:${i}`,
  principal_id: "principal:reader", resource: "data:example", observed_at: null, binding_ids: [`grant:${i}`],
});
describe("GraphHopAuthority", () => {
  it("keeps native grant inventory distinct from evaluated decisions", () => {
    const {container} = render(<GraphHopAuthority evidence={{status: "recorded", decisions: [], derivation: null, reason_codes: [], native_grants: [
      {source: "snowflake-objects", privilege: "SELECT", account: "account-a", role: "ANALYST", object_fqn: "DB.PUBLIC.ORDERS", object_type: "table"},
      {source: "snowflake-objects", privilege: "INSERT", account: null, role: null, object_fqn: "<img src=x onerror=alert(1)>", object_type: null},
    ]}} />);
    expect(screen.getByText("SELECT · Native grant")).toBeInTheDocument();
    expect(screen.getByText("INSERT · Native grant")).toBeInTheDocument();
    expect(screen.getByText("DB.PUBLIC.ORDERS")).toBeInTheDocument();
    expect(screen.getAllByText(/Session authorization and policy effects require separate evidence/)).toHaveLength(2);
    expect(screen.getAllByText("Not recorded")).toHaveLength(3);
    expect(screen.queryByText(/· allow/)).not.toBeInTheDocument();
    expect(container.querySelectorAll("img,script,a,iframe")).toHaveLength(0);
  });
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
