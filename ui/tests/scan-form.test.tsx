import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ScanForm } from "@/components/scan-form";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

describe("ScanForm", () => {
  it("renders a compact header without surface explainer cards", () => {
    render(<ScanForm />);

    expect(screen.getByRole("heading", { name: "New Scan" })).toBeInTheDocument();
    expect(screen.queryByText(/Direct scans/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Connectors and enterprise sources/i)).not.toBeInTheDocument();
  });

  it("exposes related surfaces as inline links", () => {
    render(<ScanForm />);

    expect(screen.getByRole("link", { name: "Data sources" })).toHaveAttribute("href", "/sources");
    expect(screen.getByRole("link", { name: "Governance" })).toHaveAttribute("href", "/governance");
    expect(screen.getByRole("link", { name: "Traces" })).toHaveAttribute("href", "/traces");
  });

  it("keeps advanced targets collapsed by default", () => {
    render(<ScanForm />);

    expect(screen.getByText("Advanced targets")).toBeInTheDocument();
    expect(screen.queryByPlaceholderText("/path/to/infra")).not.toBeVisible();
  });

  it("shows primary scan controls above the fold", () => {
    render(<ScanForm />);

    expect(screen.getByText("Docker images")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Start scan/i })).toBeInTheDocument();
  });
});
