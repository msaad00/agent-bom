import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TextField } from "@/components/text-field";
import { EvidenceFields } from "@/components/evidence-fields";

describe("Shared operator form and evidence components", () => {
  it("associates labels, help and validation with the editable control", () => {
    const change = vi.fn();
    render(<TextField label="Owner" hint="Team responsible for the source" error="Owner is required" onChange={change} />);
    const field = screen.getByRole("textbox", { name: "Owner" });
    expect(field).toHaveAccessibleDescription("Team responsible for the source Owner is required");
    expect(field).toHaveAttribute("aria-invalid", "true");
    fireEvent.change(field, { target: { value: "security" } });
    expect(change).toHaveBeenCalledOnce();
  });

  it("preserves caller identifiers and disabled controls without duplicate ids", () => {
    render(<><TextField id="schedule-name" label="Name" disabled /><TextField label="Name" /></>);
    const fields = screen.getAllByRole("textbox", { name: "Name" });
    expect(fields[0]).toHaveAttribute("id", "schedule-name");
    expect(fields[0]).toBeDisabled();
    expect(fields[1]!.id).not.toBe(fields[0]!.id);
    expect(fields[1]).not.toHaveAttribute("aria-invalid");
  });

  it("keeps missing evidence explicit and pairs terms with values", () => {
    render(<EvidenceFields label="Recorded evidence" fields={[
      { label: "Authentication", value: "Not recorded" },
      { label: "Verified reads", value: "None recorded", wide: true },
    ]} />);
    const panel = screen.getByRole("region", { name: "Recorded evidence" });
    expect(within(panel).getAllByRole("term")).toHaveLength(2);
    expect(within(panel).getAllByRole("definition").map(node => node.textContent)).toEqual(["Not recorded", "None recorded"]);
  });
});

describe("Shared workflow feedback", () => {
  it("announces a busy compact loading state", async () => {
    const { PageLoadingState } = await import("@/components/states/page-loading-state");
    render(<PageLoadingState compact title="Loading sources" detail="Reading saved connections" />);
    expect(screen.getByRole("status")).toHaveAttribute("aria-busy", "true");
  });

  it("announces errors and keeps the retry action usable", async () => {
    const { ErrorBanner } = await import("@/components/empty-state");
    const retry = vi.fn();
    render(<ErrorBanner compact message="Connection unavailable" onRetry={retry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Connection unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledOnce();
  });
});
