import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  InvestigationStepStrip,
  parseInvestigationStep,
} from "@/components/investigation-step-strip";

describe("InvestigationStepStrip", () => {
  it("parses step query values with a safe default", () => {
    expect(parseInvestigationStep("expand")).toBe("expand");
    expect(parseInvestigationStep("impact")).toBe("impact");
    expect(parseInvestigationStep("fix")).toBe("fix");
    expect(parseInvestigationStep(null)).toBe("path");
    expect(parseInvestigationStep("nope")).toBe("path");
  });

  it("notifies when the operator advances a step", async () => {
    const user = userEvent.setup();
    const onStepChange = vi.fn();
    render(<InvestigationStepStrip step="path" onStepChange={onStepChange} />);
    await user.click(screen.getByRole("button", { name: /Expand/i }));
    expect(onStepChange).toHaveBeenCalledWith("expand");
  });

  it("marks the active step for assistive tech", () => {
    render(<InvestigationStepStrip step="impact" onStepChange={vi.fn()} />);
    expect(screen.getByRole("button", { name: /Impact/i })).toHaveAttribute(
      "aria-current",
      "step",
    );
  });
});
