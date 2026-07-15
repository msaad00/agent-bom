import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  api: { reportClientError: vi.fn().mockResolvedValue(undefined) },
}));

import ErrorBoundary from "@/app/error";

describe("route error boundary", () => {
  it("renders a top-level heading inside a main landmark", () => {
    render(<ErrorBoundary error={new Error("boom")} reset={() => {}} />);

    const heading = screen.getByRole("heading", { level: 1, name: /something went wrong/i });
    expect(heading).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.getByText("boom")).toBeInTheDocument();
  });
});
