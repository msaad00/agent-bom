import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import GovernancePage from "@/app/governance/page";

const { apiMock, demoMode } = vi.hoisted(() => ({
  apiMock: { getGovernance: vi.fn() },
  demoMode: { isDemoMode: true, loading: false },
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

vi.mock("@/hooks/use-demo-mode", () => ({
  useDemoMode: () => demoMode,
}));

vi.mock("@/lib/theme-colors", () => ({
  useChartTheme: () => ({}),
}));

describe("GovernancePage public demo", () => {
  beforeEach(() => {
    apiMock.getGovernance.mockReset();
    demoMode.isDemoMode = true;
    demoMode.loading = false;
  });

  it("does not request or expose backend setup diagnostics", () => {
    render(<GovernancePage />);

    expect(screen.getByTestId("governance-public-demo")).toHaveTextContent(/not configured on this public demo/i);
    expect(screen.queryByText(/pip install/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SNOWFLAKE_ACCOUNT/i)).not.toBeInTheDocument();
    expect(apiMock.getGovernance).not.toHaveBeenCalled();
  });
});
