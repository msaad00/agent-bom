import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ScanForm } from "@/components/scan-form";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({
    counts: {
      deployment_mode: "local",
      scan_count: 1,
      has_local_scan: true,
    },
    loading: false,
    error: null,
  }),
}));

describe("ScanForm", () => {
  it("renders deployment-aware scan targets instead of a single image upload surface", () => {
    render(<ScanForm />);

    expect(screen.getByRole("heading", { name: "New Scan" })).toBeInTheDocument();
    expect(screen.getByText("Local")).toBeInTheDocument();
    expect(screen.getByText("Local control plane.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Cloud accounts/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Workstation/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Containers/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Kubernetes/i })).toBeInTheDocument();
    expect(screen.queryByText("Upload .txt")).not.toBeInTheDocument();
  });

  it("routes cloud scans to connectors instead of starting a direct job", async () => {
    const user = userEvent.setup();
    render(<ScanForm />);

    await user.click(screen.getByRole("button", { name: /Cloud accounts/i }));
    expect(screen.getByRole("link", { name: /Open cloud accounts/i })).toHaveAttribute("href", "/connections");
    expect(screen.getByRole("button", { name: /Use cloud accounts for scheduled scans/i })).toBeDisabled();
  });

  it("explains kubernetes namespace scope in plain language", async () => {
    const user = userEvent.setup();
    render(<ScanForm />);

    await user.click(screen.getByRole("button", { name: /Kubernetes/i }));
    await user.click(screen.getByRole("checkbox", { name: /Scan running pods/i }));
    expect(screen.getByLabelText("Namespace filter")).toBeInTheDocument();
    expect(screen.getByText(/Leave blank to scan every namespace/i)).toBeInTheDocument();
  });
});
