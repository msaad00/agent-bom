import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ActivityPage from "@/app/activity/page";
import { api } from "@/lib/api";

const { navState, replaceMock } = vi.hoisted(() => ({
  navState: { search: "days=90" },
  replaceMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/activity",
  useRouter: () => ({ replace: replaceMock }),
  useSearchParams: () => new URLSearchParams(navState.search),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, getActivity: vi.fn() } };
});

vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  BarChart: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  CartesianGrid: () => null,
}));

const timeline = {
  schema_version: "activity.timeline.v2",
  tenant_id: "tenant-a",
  window_days: 90,
  event_count: 0,
  events: [],
  truncated: false,
  sources: [],
  status: "empty",
};

beforeEach(() => {
  replaceMock.mockReset();
  navState.search = "days=90";
  vi.mocked(api.getActivity).mockReset().mockResolvedValue(timeline as never);
});

describe("Activity server filter contract", () => {
  it("loads the URL-owned time window and writes changes back to the URL", async () => {
    render(<ActivityPage />);

    await waitFor(() => expect(api.getActivity).toHaveBeenCalledWith(90));
    const windowSelect = await screen.findByLabelText("Activity time window");
    expect(windowSelect).toHaveValue("90");

    fireEvent.change(windowSelect, { target: { value: "7" } });

    await waitFor(() => expect(api.getActivity).toHaveBeenCalledWith(7));
    expect(replaceMock).toHaveBeenCalledWith("/activity?days=7", { scroll: false });
  });

  it("rejects an unsupported URL window before calling the server", async () => {
    navState.search = "days=9999";
    render(<ActivityPage />);

    await waitFor(() => expect(api.getActivity).toHaveBeenCalledWith(30));
  });
});

describe("Activity header count", () => {
  it("counts the events the stream lists instead of reporting zero above them", async () => {
    const feed = vi.spyOn(api, "getGatewayFeed").mockResolvedValue({
      events: [
        { event_id: "g-1", ts: "2026-10-08T12:00:00Z", agent: "claims-triage", action_type: "llm_call", target: "openai/gpt-5", tenant: "t", shadow: false, source: "gateway" },
        { event_id: "g-2", ts: "2026-10-08T12:01:00Z", agent: "prior-auth", action_type: "llm_call", target: "anthropic/model", tenant: "t", shadow: false, source: "gateway" },
      ],
      health: { state: "sample", live: false },
    } as never);
    render(<ActivityPage />);

    expect(
      await screen.findByText("2 recent stream events · 0 runtime events in the last 90 days"),
    ).toBeInTheDocument();
    expect(screen.queryByText(/^0 events across/)).not.toBeInTheDocument();
    feed.mockRestore();
  });
});
