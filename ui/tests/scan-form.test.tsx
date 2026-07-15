import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { ScanForm } from "@/components/scan-form";
import { api } from "@/lib/api";

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

const mockConnection = {
  id: "conn-aws-1",
  tenant_id: "default",
  provider: "aws",
  display_name: "Prod AWS",
  role_ref: "arn:aws:iam::123456789012:role/AgentBomReadOnly",
  has_external_id: true,
  regions: ["us-east-1"],
  status: "active",
  status_detail: "",
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  last_scan_at: null,
  last_event_at: null,
  last_scan_id: null,
  scan_interval_minutes: null,
  auth_params: {},
};

describe("ScanForm", () => {
  beforeEach(() => {
    vi.spyOn(api, "listCloudConnections").mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "default",
      connections: [mockConnection],
      count: 1,
    });
    vi.spyOn(api, "listSources").mockResolvedValue({
      sources: [],
      count: 0,
    });
  });

  it("renders where-am-i-scanning modes and scope summary", async () => {
    const user = userEvent.setup();
    render(<ScanForm />);

    expect(screen.getByRole("heading", { name: "New Scan" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Cloud account" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Ad-hoc" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Data source" })).toBeInTheDocument();
    expect(screen.getByText("Scope")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Cloud account" }));
    await waitFor(() => {
      expect(screen.getByText("Read-only inventory + CIS")).toBeInTheDocument();
    });
  });

  it("preselects a connected account from the query param", async () => {
    render(<ScanForm initialConnectionId="conn-aws-1" />);

    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: "Account" })).toHaveValue("conn-aws-1");
    });
    expect(screen.getByRole("button", { name: /Run cloud scan/i })).toBeEnabled();
    expect(screen.getByText("Prod AWS")).toBeInTheDocument();
  });

  it("pre-fills the enterprise introspection preset from the URL", async () => {
    render(<ScanForm initialPreset="enterprise" />);

    // Enterprise preset lands on the ad-hoc workstation introspection scan…
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: "Ad-hoc" })).toHaveAttribute(
        "aria-selected",
        "true",
      );
    });
    expect(screen.getByRole("tab", { name: /Workstation/i })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // …with enrichment turned on, mirroring `--preset enterprise`.
    expect(
      screen.getByRole("checkbox", { name: /Enrich with CVSS/i }),
    ).toBeChecked();
  });

  it("leaves enrichment off when no preset is present", async () => {
    const user = userEvent.setup();
    render(<ScanForm />);

    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    expect(
      screen.getByRole("checkbox", { name: /Enrich with CVSS/i }),
    ).not.toBeChecked();
  });

  it("shows ad-hoc scope chips and starts a direct scan job", async () => {
    const user = userEvent.setup();
    const startScan = vi.spyOn(api, "startScan").mockResolvedValue({
      job_id: "job-123",
      status: "pending",
      created_at: "2026-01-01T00:00:00Z",
      request: {},
      progress: [],
    });

    render(<ScanForm />);
    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    expect(screen.getByText("Scope")).toBeInTheDocument();
    expect(screen.getByText(/Local MCP configs on control plane host/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Start scan/i }));
    expect(startScan).toHaveBeenCalled();
  });

  it("runs a brokered cloud scan for the selected connection", async () => {
    const user = userEvent.setup();
    const scanCloudConnection = vi.spyOn(api, "scanCloudConnection").mockResolvedValue({
      schema_version: "cloud.connections.scan.v1",
      connection_id: "conn-aws-1",
      tenant_id: "default",
      provider: "aws",
      scan_id: "scan-abc",
      inventory: {
        provider: "aws",
        account: "123456789012",
        region: "us-east-1",
        resource_count: 1,
        identity_count: 1,
        node_summary: {
          buckets: 0,
          instances: 0,
          security_groups: 0,
          roles: 0,
          users: 0,
        },
        warnings: [],
      },
      cis_benchmark: {
        benchmark: "CIS AWS",
        benchmark_version: "1.5",
        passed: 1,
        failed: 0,
        total: 1,
        pass_rate: 1,
      },
      audit_metadata: {
        read_only: true,
        writes_performed: false,
        note: "Read-only scan.",
      },
      connection: mockConnection,
    });

    render(<ScanForm initialConnectionId="conn-aws-1" />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Run cloud scan/i })).toBeEnabled();
    });
    await user.click(screen.getByRole("button", { name: /Run cloud scan/i }));
    expect(scanCloudConnection).toHaveBeenCalledWith("conn-aws-1");
  });

  it("starts a public repository scan from a git URL", async () => {
    const user = userEvent.setup();
    const startScan = vi.spyOn(api, "startScan").mockResolvedValue({
      job_id: "job-repo-1",
      status: "pending",
      created_at: "2026-01-01T00:00:00Z",
      request: { repo_url: "https://github.com/org/repo" },
      progress: [],
    });

    render(<ScanForm />);
    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    await user.click(screen.getByRole("tab", { name: /Public repo/i }));
    await user.type(
      screen.getByPlaceholderText("https://github.com/org/repo"),
      "https://github.com/org/repo",
    );
    expect(screen.getByText(/surfaces auto-detected/i)).toBeInTheDocument();
    expect(screen.getByText(/Secrets & credentials/i)).toBeInTheDocument();
    expect(screen.getByText(/not git URLs/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Scan repo/i }));
    expect(startScan).toHaveBeenCalledWith({
      repo_url: "https://github.com/org/repo",
      enrich: false,
    });
  });

  it("blocks submit and flags an invalid public repository URL", async () => {
    const user = userEvent.setup();

    render(<ScanForm />);
    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    await user.click(screen.getByRole("tab", { name: /Public repo/i }));

    const input = screen.getByPlaceholderText("https://github.com/org/repo");
    await user.type(input, "github.com/org/repo");

    expect(screen.getByText(/Enter a full http\(s\):\/\/ URL/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Scan repo/i })).toBeDisabled();
  });

  it("explains kubernetes namespace scope in plain language", async () => {
    const user = userEvent.setup();
    render(<ScanForm />);

    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    const k8sTarget = screen.getByRole("tab", { name: /Kubernetes/i });
    await user.click(k8sTarget);
    await user.click(screen.getByRole("checkbox", { name: /Scan pods in current kube context/i }));
    expect(screen.getByLabelText("Namespace filter")).toBeInTheDocument();
  });
});
