import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { ScanForm } from "@/components/scan-form";
import { api, type AuthMeResponse } from "@/lib/api";

const authState = vi.hoisted(() => ({
  capabilities: ["inventory.read", "scan.run"],
  authMethod: "no_auth",
  managedTrialMode: false,
  role: "analyst",
}));

vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => {
    const session: AuthMeResponse = {
      authenticated: true,
      auth_required: authState.authMethod !== "no_auth",
      configured_modes: [],
      recommended_ui_mode: authState.authMethod,
      auth_method: authState.authMethod,
      managed_trial_mode: authState.managedTrialMode,
      subject: null,
      tenant_id: "default",
      role: authState.role,
      role_summary: {
        role: authState.role,
        ui_role: authState.role === "analyst" ? "contributor" : authState.role,
        display_name: authState.role === "analyst" ? "Contributor" : "Viewer",
        description: "Test role",
        capabilities: authState.capabilities,
        capability_matrix: [],
        can_see: [],
        can_do: [],
        cannot_do: [],
      },
      memberships: [],
      request_id: null,
      trace_id: null,
      span_id: null,
    };
    return {
      session,
      loading: false,
      error: null,
      reconnecting: false,
      refresh: vi.fn(),
      hasCapability: (capability: string) => authState.capabilities.includes(capability),
    };
  },
}));

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
  credential_present: true,
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
  capability_probe_status: "verified",
  verified_capabilities: ["bedrock:list-agents"],
};

const mockSource = {
  source_id: "source-repo-1",
  tenant_id: "default",
  display_name: "Repository source",
  kind: "scan.repo" as const,
  description: "",
  owner: "",
  connector_name: null,
  credential_mode: "none" as const,
  credential_ref: null,
  enabled: true,
  status: "configured" as const,
  config: { scan_request: { repo_url: "https://example.com/acme/repo" } },
  last_tested_at: null,
  last_test_status: null,
  last_test_message: null,
  last_run_at: null,
  last_run_status: null,
  last_job_id: null,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

describe("ScanForm", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authState.capabilities = ["inventory.read", "scan.run"];
    authState.authMethod = "no_auth";
    authState.managedTrialMode = false;
    authState.role = "analyst";
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
    expect(screen.getByText("Scope now")).toBeInTheDocument();
    expect(screen.getByText("What this scan collects and produces")).toBeInTheDocument();
    expect(screen.getByText("Read-only boundary")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText(/Agent and MCP discovery/)).toBeInTheDocument();
    });
    expect(screen.getByRole("link", { name: "Scan jobs" })).toHaveAttribute("href", "/jobs");

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
    expect(screen.getByText("Scope now")).toBeInTheDocument();
    expect(screen.getByText(/Local MCP configs on control plane host/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Start scan/i }));
    expect(startScan).toHaveBeenCalled();
  });

  it("runs a brokered cloud scan for the selected connection", async () => {
    const user = userEvent.setup();
    const scanCloudConnection = vi.spyOn(api, "scanCloudConnection").mockResolvedValue({
      schema_version: "cloud.connections.scan.accepted.v1",
      connection_id: "conn-aws-1",
      tenant_id: "default",
      provider: "aws",
      job_id: "scan-abc",
      status: "pending",
    });

    render(<ScanForm initialConnectionId="conn-aws-1" />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Run cloud scan/i })).toBeEnabled();
    });
    await user.click(screen.getByRole("button", { name: /Run cloud scan/i }));
    expect(scanCloudConnection).toHaveBeenCalledWith("conn-aws-1");
  });

  it("keeps direct cloud-scan routes read-only without scan.run", async () => {
    authState.capabilities = ["inventory.read"];
    authState.role = "viewer";
    const scanCloudConnection = vi.spyOn(api, "scanCloudConnection");

    render(<ScanForm initialConnectionId="conn-aws-1" />);

    const runButton = await screen.findByRole("button", { name: /Run cloud scan/i });
    expect(runButton).toBeDisabled();
    expect(screen.getByText(/Scans require the Contributor role or higher/i)).toBeInTheDocument();
    await userEvent.click(runButton);
    expect(scanCloudConnection).not.toHaveBeenCalled();
  });

  it("intersects role capabilities with the managed-trial route envelope", async () => {
    authState.authMethod = "managed_trial_oidc";
    authState.managedTrialMode = true;
    const user = userEvent.setup();
    const startScan = vi.spyOn(api, "startScan");

    render(<ScanForm initialConnectionId="conn-aws-1" />);

    expect(await screen.findByRole("button", { name: /Run cloud scan/i })).toBeEnabled();
    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    expect(screen.getByRole("button", { name: /Start scan/i })).toBeDisabled();
    expect(screen.getByText(/Managed trial scans run from a verified AWS connection/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Start scan/i }));
    expect(startScan).not.toHaveBeenCalled();
  });

  it("applies the managed-trial route envelope to a non-OIDC principal", async () => {
    authState.authMethod = "api_key";
    authState.managedTrialMode = true;
    const user = userEvent.setup();
    const startScan = vi.spyOn(api, "startScan");

    render(<ScanForm initialConnectionId="conn-aws-1" />);

    expect(await screen.findByRole("button", { name: /Run cloud scan/i })).toBeEnabled();
    await user.click(screen.getByRole("tab", { name: "Ad-hoc" }));
    expect(screen.getByRole("button", { name: /Start scan/i })).toBeDisabled();
    expect(startScan).not.toHaveBeenCalled();
  });

  it("keeps denied operational reads unavailable instead of reporting factual zero", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "listSources").mockRejectedValue(new Error("Forbidden"));

    render(<ScanForm initialConnectionId="conn-aws-1" />);

    await user.click(screen.getByRole("tab", { name: "Data source" }));
    expect(await screen.findByText("Data sources are unavailable for this session.")).toBeInTheDocument();
  });

  it.each([
    {
      name: "push source",
      source: { ...mockSource, kind: "ingest.result_push" as const },
      reason: /receive evidence externally and cannot run directly/i,
    },
    {
      name: "credential-bound source",
      source: {
        ...mockSource,
        credential_mode: "reference" as const,
        credential_ref: "credential-metadata",
      },
      reason: /governance metadata and cannot execute this source/i,
    },
  ])("does not offer a runnable action for a $name", async ({ source, reason }) => {
    vi.spyOn(api, "listSources").mockResolvedValue({ sources: [source], count: 1 });
    const runSource = vi.spyOn(api, "runSource");
    const user = userEvent.setup();

    render(<ScanForm />);
    await user.click(screen.getByRole("tab", { name: "Data source" }));

    const button = await screen.findByRole("button", { name: /Run source/i });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", expect.stringMatching(reason));
    await user.click(button);
    expect(runSource).not.toHaveBeenCalled();
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
    expect(screen.getByText(/dependencies, SBOM, secrets/i)).toBeInTheDocument();
    expect(screen.getByText(/Repository code is not executed/i)).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /Artifact after scan/i })).toHaveValue("json");
    await user.selectOptions(
      screen.getByRole("combobox", { name: /Artifact after scan/i }),
      "cyclonedx",
    );
    await user.click(screen.getByRole("button", { name: /Scan repository/i }));
    expect(startScan).toHaveBeenCalledWith({
      repo_url: "https://github.com/org/repo",
      enrich: false,
      format: "cyclonedx",
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
    expect(screen.getByRole("button", { name: /Scan repository/i })).toBeDisabled();
  });

  it("surfaces the AI/ML supply-chain scan panel from its own tab", async () => {
    const user = userEvent.setup();
    render(<ScanForm />);

    await user.click(screen.getByRole("tab", { name: /AI \/ ML/i }));
    expect(screen.getByTestId("ai-scan-panel")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Dataset cards/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Prompt scan/i })).toBeInTheDocument();
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
