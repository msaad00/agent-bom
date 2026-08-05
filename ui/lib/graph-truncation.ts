import type { GraphCompleteness, GraphPagination } from "@/lib/api-types";

/**
 * Whether a graph response is a partial view of its estate.
 *
 * Two independent cuts reach the canvas and only one of them is visible in
 * `pagination`:
 *
 * - the **page limit** — the caller asked for fewer rows than exist
 *   (`pagination.has_more`, `completeness.reason = "node_page_limit"`);
 * - the **load-time node budget** — `GET /v1/graph`'s investigation branch
 *   materializes the snapshot under `AGENT_BOM_GRAPH_INVESTIGATION_NODE_BUDGET`
 *   and pages whatever survived, so the last page of a *trimmed* estate reports
 *   `has_more: false` while `completeness.truncated` is the only record that
 *   nodes were dropped before paging ever started
 *   (`completeness.reason = "node_budget"`).
 *
 * `completeness` is authoritative because the server folds both cuts into it;
 * `pagination` remains the fallback for a response that predates the block.
 */
export function graphResponseIsTruncated(
  response:
    | {
        pagination?: GraphPagination | undefined;
        completeness?: GraphCompleteness | undefined;
      }
    | null
    | undefined,
): boolean {
  if (!response) return false;
  if (response.completeness) return response.completeness.truncated === true;
  return response.pagination?.has_more === true;
}
