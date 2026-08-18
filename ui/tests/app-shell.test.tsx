import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AppShell } from "@/components/app-shell";

vi.mock("next/navigation", () => ({
  usePathname: () => "/",
}));

vi.mock("@/components/auth-gate", () => ({
  AuthGate: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("@/components/demo-estate-label", () => ({ DemoEstateLabel: () => null }));
vi.mock("@/components/nav", () => ({ Nav: () => null }));

describe("AppShell", () => {
  it("uses the ultrawide workspace instead of leaving 1400px of content between symmetric gutters", () => {
    render(
      <AppShell>
        <div>Workspace content</div>
      </AppShell>,
    );

    const content = screen.getByText("Workspace content").parentElement;
    expect(content).toHaveClass("w-full", "max-w-[1920px]");
    expect(content).not.toHaveClass("max-w-[1400px]");
  });
});
