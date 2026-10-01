import { act, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { GraphSnapshotUpdates } from "@/components/graph-snapshot-updates";
import { newerGraphSnapshot, useNewerGraphSnapshot } from "@/hooks/use-newer-graph-snapshot";
import type { GraphSnapshot } from "@/lib/api-types";
import { api } from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
const state = vi.hoisted(() => ({ query: "lens=lineage&scan=old&root=agent%3Aone&finding=f-1&finding_scan=original", session: { tenant_id: "one" } as { tenant_id: string } | null }));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams(state.query) }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ loading: false, session: state.session }) }));
vi.mock("@/lib/api", () => ({ api: { getGraphSnapshots: vi.fn() } }));
const fetchSnapshots = vi.mocked(api.getGraphSnapshots);
const snapshot = (scan_id: string, created_at: string, snapshot_kind: "scan" | "correlation" = "scan"): GraphSnapshot => ({ scan_id, created_at, snapshot_kind, node_count: 2, edge_count: 1, risk_summary: {} });
const old = snapshot("old", "2026-09-30T10:00:00Z");
const newer = snapshot("new/+ ?", "2026-09-30T11:00:00Z");
beforeEach(() => { fetchSnapshots.mockReset(); state.session = { tenant_id: "one" }; state.query = "lens=lineage&scan=old&root=agent%3Aone&finding=f-1&finding_scan=original"; });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

it("offers an explicit link without switching snapshot and preserves investigation context", async () => {
  fetchSnapshots.mockResolvedValue([newer, old]);
  render(<GraphSnapshotUpdates />);
  const link = await screen.findByRole("link", { name: "Open newer snapshot" });
  const target = new URL(link.getAttribute("href")!, "https://control.example");
  expect(target.searchParams.get("scan")).toBe(newer.scan_id);
  expect(target.searchParams.get("root")).toBe("agent:one");
  expect(target.searchParams.get("finding_scan")).toBe("original");
  expect(window.location.search).not.toContain("new");
  fireEvent.click(screen.getByRole("button", { name: "Keep current" }));
  expect(screen.queryByRole("link", { name: "Open newer snapshot" })).toBeNull();
  expect(screen.getByRole("status")).toHaveTextContent("pinned");
});

it("does not mix correlation snapshots, equal timestamps, or missing historical selection", () => {
  expect(newerGraphSnapshot([old, snapshot("other-kind", "2026-10-01", "correlation")], "old")).toBeNull();
  expect(newerGraphSnapshot([old, snapshot("equal", old.created_at)], "old")).toBeNull();
  expect(newerGraphSnapshot([newer], "old")).toBeNull();
  expect(newerGraphSnapshot([old, snapshot("invalid", "invalid")], "old")).toBeNull();
});

it("keeps routine polling out of the canvas layout while announcing the pinned state", async () => {
  fetchSnapshots.mockResolvedValue([old]);
  render(<GraphSnapshotUpdates />);
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Viewing a pinned snapshot"));
  expect(screen.getByRole("status")).toHaveClass("sr-only");
  expect(screen.queryByRole("complementary", { name: "Saved snapshot updates" })).toBeNull();
});

it("clears a previous tenant's offer and ignores its in-flight response", async () => {
  let resolve!: (items: GraphSnapshot[]) => void;
  fetchSnapshots.mockImplementationOnce(() => new Promise(done => { resolve = done; })).mockResolvedValue([old]);
  const { rerender } = render(<GraphSnapshotUpdates />);
  await waitFor(() => expect(fetchSnapshots).toHaveBeenCalledTimes(1));
  const signal = fetchSnapshots.mock.calls[0]![2]!.signal!;
  state.session = { tenant_id: "two" }; rerender(<GraphSnapshotUpdates />);
  expect(signal.aborted).toBe(true);
  await act(async () => resolve([newer, old]));
  await waitFor(() => expect(fetchSnapshots).toHaveBeenCalledTimes(2));
  expect(screen.queryByRole("link", { name: "Open newer snapshot" })).toBeNull();
});

it("does not check without a session or in capture/scenario mode", () => {
  state.session = null;
  const { rerender } = render(<GraphSnapshotUpdates />);
  state.session = { tenant_id: "one" }; state.query += "&capture=1"; rerender(<GraphSnapshotUpdates />);
  state.query = "scan=old&scenario=planned"; rerender(<GraphSnapshotUpdates />);
  expect(fetchSnapshots).not.toHaveBeenCalled();
});

it("polls bounded metadata and stops background retries after denied access", async () => {
  vi.useFakeTimers();
  fetchSnapshots.mockResolvedValueOnce([old]).mockRejectedValue(new ApiError("denied", { status: 403, statusText: "Forbidden", url: "/snapshots", method: "GET" }));
  const { result, unmount } = renderHook(() => useNewerGraphSnapshot("old", "tenant", true));
  await act(async () => {});
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(result.current.error).toBe(true);
  expect(result.current.newer).toBeNull();
  await act(async () => vi.advanceTimersByTimeAsync(90_000));
  expect(fetchSnapshots).toHaveBeenCalledTimes(2);
  expect(fetchSnapshots.mock.calls[0]!.slice(0, 2)).toEqual([40, 0]);
  unmount();
});

it("treats an unavailable selected snapshot as unknown, not up to date", async () => {
  fetchSnapshots.mockResolvedValue([newer]);
  render(<GraphSnapshotUpdates />);
  expect(await screen.findByText(/update check unavailable/)).toBeVisible();
  expect(screen.queryByRole("link")).toBeNull();
});
