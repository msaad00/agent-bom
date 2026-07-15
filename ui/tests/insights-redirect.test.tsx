import { describe, expect, it, vi } from "vitest";

const { redirectMock } = vi.hoisted(() => ({ redirectMock: vi.fn() }));

vi.mock("next/navigation", () => ({ redirect: redirectMock }));

import InsightsRedirect from "@/app/insights/page";

describe("insights redirect", () => {
  it("redirects to the dashboard home honestly (no ignored ?tab suffix)", () => {
    InsightsRedirect();
    expect(redirectMock).toHaveBeenCalledWith("/");
    // The old target used an anchor the home page never reads.
    expect(redirectMock).not.toHaveBeenCalledWith("/?tab=analytics");
  });
});
