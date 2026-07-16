import { describe, expect, it, vi, beforeEach } from "vitest";

const { redirectMock } = vi.hoisted(() => ({ redirectMock: vi.fn() }));

vi.mock("next/navigation", () => ({ redirect: redirectMock }));

import SourcesRedirect from "@/app/sources/page";

describe("SourcesRedirect", () => {
  beforeEach(() => {
    redirectMock.mockClear();
  });

  it("routes /sources to the Connections hub Sources segment", () => {
    SourcesRedirect();
    expect(redirectMock).toHaveBeenCalledWith("/connections?tab=sources");
  });
});
