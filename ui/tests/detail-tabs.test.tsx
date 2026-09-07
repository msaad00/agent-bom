import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { DetailTabs } from "@/components/detail-tabs";

function Tabs() {
  const [value, setValue] = useState("overview");
  return <DetailTabs tabs={[{ key: "overview", label: "Overview" }, { key: "evidence", label: "Evidence" }, { key: "triage", label: "Triage" }]} value={value} onChange={setValue} ariaLabel="Finding details" />;
}

describe("DetailTabs keyboard navigation", () => {
  it("activates and focuses tabs with arrows, Home and End, wrapping at the edges", () => {
    render(<Tabs />);
    const overview = screen.getByRole("tab", { name: "Overview" });
    const evidence = screen.getByRole("tab", { name: "Evidence" });
    const triage = screen.getByRole("tab", { name: "Triage" });
    overview.focus();
    fireEvent.keyDown(overview, { key: "ArrowRight" });
    expect(evidence).toHaveFocus();
    expect(evidence).toHaveAttribute("aria-selected", "true");
    expect(overview).toHaveAttribute("tabindex", "-1");
    fireEvent.keyDown(evidence, { key: "End" });
    expect(triage).toHaveFocus();
    expect(triage).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(triage, { key: "ArrowRight" });
    expect(overview).toHaveFocus();
    fireEvent.keyDown(overview, { key: "ArrowLeft" });
    expect(triage).toHaveFocus();
    fireEvent.keyDown(triage, { key: "Home" });
    expect(overview).toHaveFocus();
    expect(overview).toHaveAttribute("aria-selected", "true");
    expect(fireEvent.keyDown(overview, { key: "Tab" })).toBe(true);
  });
});
