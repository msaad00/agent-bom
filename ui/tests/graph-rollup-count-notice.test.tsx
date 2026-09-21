import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraphRollupCountNotice } from "@/components/graph-rollup-count-notice";
import type { GraphRollupAggregateCountMetadata } from "@/lib/api-types";

const metadata: GraphRollupAggregateCountMetadata = {
  basis: "returned_entry_descendants", definition: "Filtered descendants of returned entries; not an estate total.",
  distinct_descendants: 2, descendant_memberships: 3, shared_descendants: 1,
  extra_memberships: 1, additive: false, source_truncated: false, reason: "",
};

describe("GraphRollupCountNotice", () => {
  it("distinguishes shared memberships from unique descendants", () => {
    render(<GraphRollupCountNotice metadata={metadata} />);
    expect(screen.getByText(/This level: 2 unique descendants · 3 scope memberships/)).toBeVisible();
    expect(screen.getByText(/Shared descendants are counted in each scope/)).toBeVisible();
  });
  it("qualifies counts from a bounded source", () => {
    render(<GraphRollupCountNotice metadata={{ ...metadata, source_truncated: true, reason: "node_budget" }} />);
    expect(screen.getByText(/Loaded scope: 2 unique descendants/)).toBeVisible();
    expect(screen.queryByText(/This level/)).not.toBeInTheDocument();
  });
  it("adds no extra copy when metadata is unavailable or scopes do not overlap", () => {
    const { container, rerender } = render(<GraphRollupCountNotice />);
    expect(container).toBeEmptyDOMElement();
    rerender(<GraphRollupCountNotice metadata={{ ...metadata, extra_memberships: 0, additive: true }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
