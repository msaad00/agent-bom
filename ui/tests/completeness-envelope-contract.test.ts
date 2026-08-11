/**
 * The client-side reader of `completeness` must not be handed a shape it
 * silently misreads.
 *
 * `graphResponseIsTruncated` treats `completeness` as authoritative the moment
 * it is present — it returns `completeness.truncated === true` and stops,
 * *without* falling back to `pagination.has_more`. That is the right design
 * when the envelope is well-formed, and a trap when it is not: an envelope that
 * carries a status word but no `truncated` boolean reads as "not truncated"
 * AND suppresses the fallback that would otherwise have caught it.
 *
 * Two backend read paths used to emit exactly that shape —
 * `{"status": "partial", "reason": "node_budget", "node_budget": 50000}` — a
 * status word outside the published `GraphCompleteness` union with none of its
 * booleans. These tests pin the failure so the shape cannot come back, and pin
 * the corrected shape so a bounded read is recognised as bounded.
 */
import { describe, expect, it } from "vitest";

import { graphResponseIsTruncated } from "@/lib/graph-truncation";

const pagination = {
  total: 120_000,
  limit: 1_000,
  offset: 0,
  has_more: true,
};

describe("a completeness envelope missing its booleans", () => {
  it("reads as complete AND suppresses the pagination fallback", () => {
    // Documenting the trap, not endorsing it: `has_more` is true, so without a
    // completeness block this response is plainly truncated.
    const withoutEnvelope = graphResponseIsTruncated({ pagination });
    expect(withoutEnvelope).toBe(true);

    const legacyShape = {
      pagination,
      completeness: {
        status: "partial",
        reason: "node_budget",
      } as never,
    };
    expect(graphResponseIsTruncated(legacyShape)).toBe(false);
  });

  it("recognises the shared envelope a bounded read now emits", () => {
    expect(
      graphResponseIsTruncated({
        pagination,
        completeness: {
          status: "truncated",
          complete: false,
          sampled: false,
          truncated: true,
          returned: 50_000,
          reason: "node_budget",
        },
      }),
    ).toBe(true);
  });

  it("still reads an exhaustive read as exhaustive", () => {
    expect(
      graphResponseIsTruncated({
        pagination: { ...pagination, total: 7, has_more: false },
        completeness: {
          status: "complete",
          complete: true,
          sampled: false,
          truncated: false,
          returned: 7,
        },
      }),
    ).toBe(false);
  });
});
