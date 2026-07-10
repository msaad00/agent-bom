import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Collapsible } from "@/components/collapsible";

describe("Collapsible", () => {
  it("toggles aria-expanded and panel visibility on click", () => {
    render(
      <Collapsible title="Findings" count={3}>
        <p>panel body</p>
      </Collapsible>,
    );

    const button = screen.getByRole("button", { name: /Findings/ });
    const panelId = button.getAttribute("aria-controls");
    expect(panelId).toBeTruthy();

    expect(button).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("panel body")).toBeVisible();

    fireEvent.click(button);
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("panel body")).not.toBeVisible();

    fireEvent.click(button);
    expect(button).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("panel body")).toBeVisible();
  });

  it("respects defaultOpen=false", () => {
    render(
      <Collapsible title="Closed" defaultOpen={false}>
        <p>hidden body</p>
      </Collapsible>,
    );
    const button = screen.getByRole("button", { name: /Closed/ });
    expect(button).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByText("hidden body")).not.toBeVisible();
  });

  it("applies in-panel scroll max-height when requested", () => {
    render(
      <Collapsible title="Scrollable" scrollMaxHeight="12rem">
        <p>tall body</p>
      </Collapsible>,
    );
    const button = screen.getByRole("button", { name: /Scrollable/ });
    const panel = document.getElementById(button.getAttribute("aria-controls")!);
    expect(panel).toHaveStyle({ maxHeight: "12rem", overflowY: "auto" });
  });

  it("renders bare nested mode without a bordered card shell", () => {
    const { container } = render(
      <Collapsible bare title="Nested" subtitle="Inside a parent card">
        <p>nested body</p>
      </Collapsible>,
    );
    expect(container.firstChild).not.toHaveClass("rounded-xl");
    expect(screen.getByText("Inside a parent card")).toBeInTheDocument();
  });
});
