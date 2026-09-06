import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import ComplianceLoading from "@/app/compliance/loading";
import FindingsLoading from "@/app/findings/loading";
import SecurityGraphLoading from "@/app/security-graph/loading";

describe("priority route loading states", () => {
  it.each([
    [FindingsLoading, "findings-route-loading", "Loading findings"],
    [SecurityGraphLoading, "security-graph-route-loading", "Loading investigation"],
    [ComplianceLoading, "compliance-route-loading", "Loading compliance"],
  ])("renders an immediate state for a data-heavy route", (LoadingState, testId, title) => {
    render(<LoadingState />);
    expect(screen.getByTestId(testId)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: title })).toBeInTheDocument();
  });
});
