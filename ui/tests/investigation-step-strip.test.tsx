import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  InvestigationStepStrip,
  parseInvestigationStep,
} from "@/components/investigation-step-strip";

describe("InvestigationStepStrip", () => {
  it("parses step query values with a safe default", () => {
    expect(parseInvestigationStep("expand")).toBe("impact");
    expect(parseInvestigationStep("impact")).toBe("impact");
    expect(parseInvestigationStep("owner")).toBe("owner");
    expect(parseInvestigationStep("fix")).toBe("fix");
    expect(parseInvestigationStep("verify")).toBe("verify");
    expect(parseInvestigationStep(null)).toBe("path");
    expect(parseInvestigationStep("nope")).toBe("path");
  });

  it("guides the complete finding lifecycle in order", () => {
    render(<InvestigationStepStrip step="impact" onStepChange={vi.fn()} />);

    const steps = screen.getAllByRole("listitem");
    expect(steps).toHaveLength(5);
    expect(steps.map((item) => item.textContent)).toEqual([
      expect.stringMatching(/1Path/),
      expect.stringMatching(/2Impact/),
      expect.stringMatching(/3Owner/),
      expect.stringMatching(/4Fix/),
      expect.stringMatching(/5Verify/),
    ]);
    expect(screen.queryByRole("button", { name: /Expand/i })).not.toBeInTheDocument();
  });

  it("notifies when the operator advances a step", async () => {
    const user = userEvent.setup();
    const onStepChange = vi.fn();
    render(<InvestigationStepStrip step="path" onStepChange={onStepChange} />);
    await user.click(screen.getByRole("button", { name: /Impact/i }));
    expect(onStepChange).toHaveBeenCalledWith("impact");
  });

  it("marks the active step for assistive tech", () => {
    render(<InvestigationStepStrip step="impact" onStepChange={vi.fn()} />);
    expect(screen.getByRole("button", { name: /Impact/i })).toHaveAttribute(
      "aria-current",
      "step",
    );
    expect(screen.getByRole("button", { name: /Impact/i })).toHaveAccessibleDescription(
      /blast radius/i,
    );
  });

  it("uses continuation links without creating another workflow surface", () => {
    render(
      <InvestigationStepStrip
        step="impact"
        onStepChange={vi.fn()}
        stepHrefs={{ owner: "/remediation#campaigns", fix: "/remediation#campaigns", verify: "/remediation#verification" }}
      />,
    );

    expect(screen.getByRole("link", { name: /Owner/i })).toHaveAttribute(
      "href",
      "/remediation#campaigns",
    );
    expect(screen.getByRole("link", { name: /Verify/i })).toHaveAttribute(
      "href",
      "/remediation#verification",
    );
  });
});
