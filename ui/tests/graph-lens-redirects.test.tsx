import { render } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

import MeshRedirectPage from "@/app/mesh/page";
import ContextRedirectPage from "@/app/context/page";

const replace = vi.fn();
let params = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace }),
  useSearchParams: () => params,
}));

describe("retired lens routes redirect to the unified /graph surface", () => {
  beforeEach(() => {
    replace.mockClear();
    params = new URLSearchParams();
  });

  it("redirects /mesh to /graph?lens=mesh (no 404)", () => {
    render(<MeshRedirectPage />);
    expect(replace).toHaveBeenCalledWith("/graph?lens=mesh");
  });

  it("redirects /context to /graph?lens=context (no 404)", () => {
    render(<ContextRedirectPage />);
    expect(replace).toHaveBeenCalledWith("/graph?lens=context");
  });

  it("preserves deep-link query params through the /mesh redirect", () => {
    params = new URLSearchParams({ scan: "scan-9", agent: "payments" });
    render(<MeshRedirectPage />);
    expect(replace).toHaveBeenCalledWith(
      "/graph?scan=scan-9&agent=payments&lens=mesh",
    );
  });

  it("preserves deep-link query params through the /context redirect", () => {
    params = new URLSearchParams({ scan: "scan-9", agent: "payments" });
    render(<ContextRedirectPage />);
    expect(replace).toHaveBeenCalledWith(
      "/graph?scan=scan-9&agent=payments&lens=context",
    );
  });

  it("overrides a stale lens param on the retired route", () => {
    params = new URLSearchParams({ lens: "context" });
    render(<MeshRedirectPage />);
    expect(replace).toHaveBeenCalledWith("/graph?lens=mesh");
  });
});
