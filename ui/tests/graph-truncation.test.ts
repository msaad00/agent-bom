import { describe, expect, it } from "vitest";

import type { GraphCompleteness, GraphPagination } from "@/lib/api-types";
import { graphResponseIsTruncated } from "@/lib/graph-truncation";

function pagination(hasMore: boolean, total = 100): GraphPagination {
  return { total, limit: 3000, offset: 0, has_more: hasMore };
}

function completeness(
  overrides: Partial<GraphCompleteness> = {},
): GraphCompleteness {
  return {
    status: "complete",
    complete: true,
    sampled: false,
    truncated: false,
    returned: 100,
    total: 100,
    ...overrides,
  };
}

describe("graphResponseIsTruncated", () => {
  it("is false when the whole snapshot came back", () => {
    expect(
      graphResponseIsTruncated({
        pagination: pagination(false),
        completeness: completeness(),
      }),
    ).toBe(false);
  });

  it("is true when the page limit cut the result", () => {
    expect(
      graphResponseIsTruncated({
        pagination: pagination(true, 5000),
        completeness: completeness({
          status: "truncated",
          complete: false,
          truncated: true,
          returned: 3000,
          total: 5000,
          reason: "node_page_limit",
        }),
      }),
    ).toBe(true);
  });

  it("is true when the LOAD-TIME node budget cut the snapshot before paging", () => {
    // GET /v1/graph's investigation branch (any relationship / static-only /
    // runtime-only filter) materializes the snapshot under
    // AGENT_BOM_GRAPH_INVESTIGATION_NODE_BUDGET and then pages what survived.
    // A 30,000-node estate trimmed to 25,000 and served as a 500-row page has
    // `has_more: false` on the LAST page while `completeness.truncated` is the
    // only record that 5,000 nodes were never loaded. Keying the banner off
    // pagination alone reported that estate as complete.
    expect(
      graphResponseIsTruncated({
        pagination: pagination(false, 25000),
        completeness: completeness({
          status: "truncated",
          complete: false,
          truncated: true,
          returned: 500,
          total: 30000,
          reason: "node_budget",
        }),
      }),
    ).toBe(true);
  });

  it("falls back to pagination when the server sent no completeness block", () => {
    expect(graphResponseIsTruncated({ pagination: pagination(true) })).toBe(
      true,
    );
    expect(graphResponseIsTruncated({ pagination: pagination(false) })).toBe(
      false,
    );
  });

  it("is false for an absent response rather than implying loss", () => {
    expect(graphResponseIsTruncated(undefined)).toBe(false);
    expect(graphResponseIsTruncated(null)).toBe(false);
  });
});
