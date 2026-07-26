import { render, screen } from "@testing-library/react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  api: { reportClientError: vi.fn().mockResolvedValue(undefined) },
}));

import ErrorBoundary from "@/app/error";
import RootErrorBoundary from "@/app/global-error";

describe("route error boundary", () => {
  it("renders a top-level heading inside a main landmark", () => {
    render(<ErrorBoundary error={new Error("boom")} reset={() => {}} />);

    const heading = screen.getByRole("heading", { level: 1, name: /something went wrong/i });
    expect(heading).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
  });

  it("never renders the raw exception text", () => {
    const secret = "connect ECONNREFUSED postgresql://user:hunter2@db.internal:5432";

    render(<ErrorBoundary error={new Error(secret)} reset={() => {}} />);

    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("hunter2");
    expect(document.body.textContent).not.toContain("db.internal");
  });

  it("reports only safe catalog text to telemetry", async () => {
    const { api } = await import("@/lib/api");
    const secret = "connect ECONNREFUSED postgresql://user:hunter2@db.internal:5432";

    render(<ErrorBoundary error={new Error(secret)} reset={() => {}} />);

    expect(api.reportClientError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: "The dashboard could not reach the control plane. Check that it is running and reachable, then try again.",
      }),
    );
    expect(api.reportClientError).not.toHaveBeenCalledWith(expect.objectContaining({ message: secret }));
  });
});

describe("root error boundary", () => {
  it("never renders the raw exception text", () => {
    const secret = "postgresql://user:hunter2@db.internal:5432";

    const markup = renderToStaticMarkup(<RootErrorBoundary error={new Error(secret)} reset={() => {}} />);

    expect(markup).not.toContain("hunter2");
    expect(markup).not.toContain("db.internal");
    expect(markup).toContain("Something went wrong");
  });
});
