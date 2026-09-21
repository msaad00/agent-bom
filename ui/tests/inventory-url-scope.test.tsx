import { act, renderHook } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { useInventoryUrlScope } from "@/lib/inventory-url-scope";

const nav = vi.hoisted(() => ({ query: "provider=aws&environment=production&type=agent&tab=assets", replace: vi.fn() }));
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(nav.query),
  usePathname: () => "/inventory",
  useRouter: () => ({ replace: nav.replace }),
}));
beforeEach(() => { nav.replace.mockReset(); nav.query = "provider=aws&environment=production&type=agent&tab=assets"; });
it("pins the resolved snapshot before later filter edits and retains unrelated navigation", () => {
  const { result } = renderHook(useInventoryUrlScope);
  expect(result.current.initialFilters).toEqual({ provider: "aws", environment: "production", type: "agent" });
  act(() => result.current.onSnapshotResolved("snapshot-42"));
  act(() => result.current.onFiltersChange({ provider: "aws", environment: "production", type: "agent", search: "payments", source: "", severity: "" }));
  const [url] = nav.replace.mock.calls.at(-1)!;
  expect(Object.fromEntries(new URL(url, "http://localhost").searchParams)).toEqual({ provider: "aws", environment: "production", type: "agent", tab: "assets", scan: "snapshot-42", search: "payments" });
});
it("restores browser Back scope and clears filters without losing its snapshot", () => {
  const { result, rerender } = renderHook(useInventoryUrlScope);
  nav.query = "scan=older&provider=gcp&source=project-a";
  rerender();
  expect(result.current.scanId).toBe("older");
  expect(result.current.initialFilters).toEqual({ provider: "gcp", source: "project-a" });
  act(() => result.current.onFiltersChange({ provider: "", environment: "", type: "", search: "", source: "", severity: "" }));
  expect(nav.replace).toHaveBeenLastCalledWith("/inventory?scan=older", { scroll: false });
});


it("restores minimum severity without treating it as exact severity", () => {
  nav.query = "scan=snapshot&min_severity=high&type=service_account";
  const { result } = renderHook(useInventoryUrlScope);
  expect(result.current.initialFilters).toEqual({ minSeverity: "high", type: "service_account" });
});
