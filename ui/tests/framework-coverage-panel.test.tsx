import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { FrameworkCoveragePanel, type FrameworkCoverageItem } from "@/components/framework-coverage-panel";

const SAMPLE_ITEMS: FrameworkCoverageItem[] = [
  { id: "owasp-llm", label: "OWASP LLM Top 10", pass: 10, warn: 0, fail: 0, total: 10, category: "ai" },
  { id: "cis", label: "CIS Controls v8", pass: 8, warn: 1, fail: 1, total: 10, category: "cloud" },
  { id: "soc2", label: "SOC 2", pass: 12, warn: 0, fail: 0, total: 12, category: "governance" },
];

describe("FrameworkCoveragePanel", () => {
  it("defaults to collapsed rows with category tabs and status filters", async () => {
    const user = userEvent.setup();
    render(<FrameworkCoveragePanel items={SAMPLE_ITEMS} />);

    expect(screen.getByTestId("framework-coverage-panel")).toBeInTheDocument();
    expect(screen.getByText("2 passing")).toBeInTheDocument();
    expect(screen.getByText("0 warning")).toBeInTheDocument();
    expect(screen.getByText("1 failing")).toBeInTheDocument();

    expect(screen.queryByText(/8 pass/i)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /CIS Controls v8/i }));
    expect(screen.getByText(/8 pass/i)).toBeInTheDocument();
  });

  it("filters by category and failing-only status", async () => {
    const user = userEvent.setup();
    render(<FrameworkCoveragePanel items={SAMPLE_ITEMS} />);

    await user.click(screen.getByRole("button", { name: "Cloud & ops" }));
    expect(screen.getByText("CIS Controls v8")).toBeInTheDocument();
    expect(screen.queryByText("OWASP LLM Top 10")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "All" }));
    await user.click(screen.getByRole("button", { name: "Failing only" }));
    expect(screen.getByText("CIS Controls v8")).toBeInTheDocument();
    expect(screen.queryByText("OWASP LLM Top 10")).not.toBeInTheDocument();
  });

  it("calls onFocusFramework when Controls is clicked", async () => {
    const user = userEvent.setup();
    const onFocus = vi.fn();
    render(<FrameworkCoveragePanel items={SAMPLE_ITEMS} onFocusFramework={onFocus} />);

    await user.click(screen.getAllByRole("button", { name: "Controls" })[0]!);
    expect(onFocus).toHaveBeenCalledWith("owasp-llm");
  });
});
