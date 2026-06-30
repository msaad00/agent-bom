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

    // defaultOpen=true → expanded and panel shown
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
});
