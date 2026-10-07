import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { GraphPathQueueContinuation } from "@/components/graph-path-queue-continuation";
import type { UnifiedGraphResponse } from "@/lib/api-types";

const graph = { pagination: { total: 50, offset: 0, limit: 25, has_more: true } } as UnifiedGraphResponse;
const defaults = { graph, matches: 0, hiddenMatches: 0, narrowed: true, loading: false, error: null, onMore: vi.fn() };

it("keeps continuation available with zero loaded matches without inventing omitted matches", () => {
  render(<GraphPathQueueContinuation {...defaults} />);
  expect(screen.getByRole("status")).toHaveTextContent("matches outside loaded pages are unknown");
  fireEvent.click(screen.getByRole("button", { name: "Load next 25 paths" }));
  expect(defaults.onMore).toHaveBeenCalledTimes(1);
  expect(screen.queryByText(/25 matching/)).toBeNull();
});

it("disables duplicate requests and retains a retry after errors", () => {
  const { rerender } = render(<GraphPathQueueContinuation {...defaults} loading />);
  expect(screen.getByRole("button")).toBeDisabled();
  rerender(<GraphPathQueueContinuation {...defaults} error="Request unavailable." />);
  expect(screen.getByRole("alert")).toHaveTextContent("Loaded evidence is retained");
  expect(screen.getByRole("button")).not.toBeDisabled();
});

it("does not call a consumed ranking window complete snapshot coverage", () => {
  render(<GraphPathQueueContinuation {...defaults} graph={{ ...graph, pagination: { ...graph.pagination, has_more: false }, count_metadata: { ranking: { complete: false, window: 20000 } } }} />);
  expect(screen.getByText(/does not establish complete snapshot coverage/)).toBeVisible();
  expect(screen.queryByRole("button")).toBeNull();
});

it("labels the actual display page size for loaded and fetched paths", () => {
  const { rerender } = render(<GraphPathQueueContinuation {...defaults} narrowed={false} hiddenMatches={17} pageSize={10} />);
  expect(screen.getByRole("button", { name: "Show 10 more" })).toBeVisible();
  rerender(<GraphPathQueueContinuation {...defaults} narrowed={false} pageSize={10} />);
  expect(screen.getByRole("button", { name: "Show 10 more" })).toBeVisible();
});
