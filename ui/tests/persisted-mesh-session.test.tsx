import { act, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { MeshLensView } from "@/components/mesh-lens-view";

const auth = vi.hoisted(() => ({ loading: false, session: { tenant_id: "tenant-a" } as { tenant_id: string } | null }));
const navigation = vi.hoisted(() => ({ query: "scan=snapshot-a&agent=agent%3Acloud" }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => auth }));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams(navigation.query) }));
vi.mock("@/lib/api", () => ({ api: { getGraphSnapshots: vi.fn().mockResolvedValue([]) } }));
vi.mock("@/components/graph-lens-switcher", () => ({ GraphLensSwitcher: () => null }));
vi.mock("@/components/persisted-context-view", () => ({ SnapshotNeighborhood: ({ initialRootId }: { initialRootId: string }) => <div>Recorded root: {initialRootId}</div> }));
beforeEach(() => { auth.loading = false; auth.session = { tenant_id: "tenant-a" }; navigation.query = "scan=snapshot-a&agent=agent%3Acloud"; });

it("prefers the canonical root over a carried agent display-name filter", async () => {
  navigation.query = "scan=snapshot-a&agent=Display+Name&root=server%3Aexact";
  render(<MeshLensView />);
  await act(async () => {});
  expect(screen.getByText("Recorded root: server:exact")).toBeVisible();
});

it("retains the mesh while an existing authenticated session refreshes", async () => {
  const view = render(<MeshLensView />);
  await act(async () => {});
  auth.loading = true;
  view.rerender(<MeshLensView />);
  expect(screen.getByText("Recorded root: agent:cloud")).toBeVisible();
  auth.session = null;
  view.rerender(<MeshLensView />);
  expect(screen.queryByText("Recorded root: agent:cloud")).not.toBeInTheDocument();
});
