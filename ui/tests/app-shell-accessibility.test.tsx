import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ usePathname: () => "/findings" }));
vi.mock("@/components/auth-gate", () => ({ AuthGate: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@/components/demo-estate-label", () => ({ DemoEstateLabel: () => null }));
vi.mock("@/components/nav", () => ({ Nav: () => null }));

import { AppShell } from "@/components/app-shell";

describe("AppShell accessibility", () => {
  it("offers a keyboard skip link to the main content", () => {
    render(<AppShell><p>Findings content</p></AppShell>);
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main-content");
    expect(screen.getByRole("main")).toHaveAttribute("id", "main-content");
  });
});
