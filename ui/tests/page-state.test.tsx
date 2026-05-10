import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: { href: string; children: ReactNode }) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";

describe("page state components", () => {
  it("renders empty state guidance with a first command and action", () => {
    render(
      <PageEmptyState
        title="No findings found"
        detail="Run a scan to populate this view."
        suggestions={["Use the demo for sample data.", "Open scan for a real run."]}
        command="agent-bom agents --demo --offline"
        action={{ label: "Open scan", href: "/scan" }}
      />,
    );

    expect(screen.getByText("No findings found")).toBeInTheDocument();
    expect(screen.getByText("agent-bom agents --demo --offline")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open scan" })).toHaveAttribute("href", "/scan");
  });

  it("renders error and loading states with stable test ids", () => {
    render(
      <>
        <PageErrorState title="Could not load agents" detail="API unavailable" data-testid="error-state" />
        <PageLoadingState title="Loading compliance posture" detail="Fetching controls." data-testid="loading-state" />
      </>,
    );

    expect(screen.getByTestId("error-state")).toHaveTextContent("Could not load agents");
    expect(screen.getByTestId("loading-state")).toHaveTextContent("Loading compliance posture");
  });
});
