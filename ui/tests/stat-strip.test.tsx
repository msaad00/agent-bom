import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { StatStrip } from "@/components/stat-strip";

describe("StatStrip", () => {
  it("renders each metric's label and value", () => {
    render(
      <StatStrip
        items={[
          { label: "Critical", value: 4, accent: "critical" },
          { label: "Coverage", value: "92%", accent: "success", hint: "+3 vs last scan" },
        ]}
      />,
    );
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("92%")).toBeInTheDocument();
    expect(screen.getByText("+3 vs last scan")).toBeInTheDocument();
  });

  it("tints the value only when a numeric value clears the threshold", () => {
    render(
      <StatStrip
        items={[
          { label: "Zero", value: 0, accent: "critical" },
          { label: "Some", value: 3, accent: "critical" },
        ]}
      />,
    );
    expect(screen.getByText("0").className).toContain("var(--foreground)");
    expect(screen.getByText("3").className).toContain("var(--severity-critical)");
  });

  it("renders a link cell when href is provided", () => {
    render(<StatStrip items={[{ label: "High", value: 12, href: "/findings" }]} />);
    expect(screen.getByRole("link")).toHaveAttribute("href", "/findings");
  });

  it("fires onClick for a button cell", () => {
    const onClick = vi.fn();
    render(<StatStrip items={[{ label: "Medium", value: 7, onClick }]} />);
    fireEvent.click(screen.getByRole("button"));
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});
