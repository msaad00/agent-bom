import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { GraphPresetControls } from "@/components/graph-preset-controls";

const listGraphPresets = vi.fn();
const saveGraphPreset = vi.fn();
const deleteGraphPreset = vi.fn();

vi.mock("@/lib/api", () => ({
  api: {
    listGraphPresets: (...args: unknown[]) => listGraphPresets(...args),
    saveGraphPreset: (...args: unknown[]) => saveGraphPreset(...args),
    deleteGraphPreset: (...args: unknown[]) => deleteGraphPreset(...args),
  },
}));

describe("GraphPresetControls", () => {
  beforeEach(() => {
    listGraphPresets.mockReset();
    saveGraphPreset.mockReset();
    deleteGraphPreset.mockReset();
    listGraphPresets.mockResolvedValue([
      {
        name: "critical-prod",
        filters: { severity: "critical", environment: "prod" },
      },
    ]);
    saveGraphPreset.mockResolvedValue({ name: "new", status: "saved" });
    deleteGraphPreset.mockResolvedValue(undefined);
  });

  it("lists presets from /v1/graph/presets and applies filters", async () => {
    const user = userEvent.setup();
    const onApply = vi.fn();
    render(
      <GraphPresetControls
        filters={{
          severity: null,
          layer: null,
          evidenceTier: null,
          environment: null,
        }}
        onApply={onApply}
      />,
    );

    await waitFor(() => expect(screen.getByRole("button", { name: "critical-prod" })).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "critical-prod" }));
    expect(onApply).toHaveBeenCalledWith({
      severity: "critical",
      layer: null,
      evidenceTier: null,
      environment: "prod",
    });
    expect(listGraphPresets).toHaveBeenCalled();
  });

  it("saves the current chip filters as a named preset", async () => {
    const user = userEvent.setup();
    render(
      <GraphPresetControls
        filters={{
          severity: "high",
          layer: "package",
          evidenceTier: "static_scan",
          environment: null,
        }}
        onApply={vi.fn()}
      />,
    );

    await waitFor(() => expect(listGraphPresets).toHaveBeenCalled());
    await user.type(screen.getByLabelText("Preset name"), "high-packages");
    await user.click(screen.getByRole("button", { name: /Save/i }));

    await waitFor(() =>
      expect(saveGraphPreset).toHaveBeenCalledWith({
        name: "high-packages",
        description: "Investigation filter preset",
        filters: {
          severity: "high",
          layer: "package",
          evidence_tier: "static_scan",
          environment: null,
        },
      }),
    );
  });
});
