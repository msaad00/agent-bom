import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import CwppSideScanPage from "@/app/cwpp/page";

const { apiMock, authState } = vi.hoisted(() => ({
  apiMock: {
    listSideScans: vi.fn(),
    triggerSideScan: vi.fn(),
    getSideScan: vi.fn(),
  },
  authState: { capabilities: ["scan.run"] as string[] },
}));

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode } & React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: { authenticated: true, tenant_id: "tenant-acme", role: "admin" },
    loading: false,
    error: null,
    refresh: vi.fn(),
    hasCapability: (capability: string) => authState.capabilities.includes(capability),
  }),
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

const CAPABILITIES = [
  { provider: "aws", target_discovery: true, lifecycle_contract: true, executor: "aws-ebs", cli_available: true, credentialed_smoke: false },
  { provider: "azure", target_discovery: true, lifecycle_contract: true, executor: "azure-managed-disk", cli_available: true, credentialed_smoke: false },
  { provider: "gcp", target_discovery: true, lifecycle_contract: true, executor: "gcp-persistent-disk", cli_available: true, credentialed_smoke: false },
];

function execution(overrides: Record<string, unknown> = {}) {
  return {
    execution_id: "exec-abcdef123456",
    provider: "gcp",
    account_id: "proj-1",
    target_id: "projects/proj-1/zones/us-central1-a/disks/os",
    status: "scan_complete",
    phase: "finished",
    cleanup_status: "complete",
    counts: { package_count: 42, vulnerability_count: 3, secret_count: 1, config_finding_count: 0, ioc_finding_count: 0 },
    failure_code: "",
    warning_codes: [],
    updated_at: "2026-08-13T00:00:00Z",
    created_at: "2026-08-13T00:00:00Z",
    ...overrides,
  };
}

beforeEach(() => {
  authState.capabilities = ["scan.run"];
  apiMock.listSideScans.mockReset();
  apiMock.triggerSideScan.mockReset();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("CWPP side-scan page", () => {
  it("renders capabilities and honest credentialed_smoke=false note", async () => {
    apiMock.listSideScans.mockResolvedValue({ tenant_id: "tenant-acme", executions: [], capabilities: CAPABILITIES, credentialed_smoke: false });
    render(<CwppSideScanPage />);
    await waitFor(() => expect(screen.getByText("Executor capabilities")).toBeInTheDocument());
    expect(screen.getByText("azure-managed-disk")).toBeInTheDocument();
    expect(screen.getByText("gcp-persistent-disk")).toBeInTheDocument();
    expect(screen.getByText(/credentialed_smoke=false/)).toBeInTheDocument();
  });

  it("shows an empty state when there are no executions", async () => {
    apiMock.listSideScans.mockResolvedValue({ tenant_id: "tenant-acme", executions: [], capabilities: CAPABILITIES, credentialed_smoke: false });
    render(<CwppSideScanPage />);
    await waitFor(() => expect(screen.getByText("No side-scan executions yet")).toBeInTheDocument());
  });

  it("renders execution rows with status and metadata-only counts", async () => {
    apiMock.listSideScans.mockResolvedValue({
      tenant_id: "tenant-acme",
      executions: [execution(), execution({ execution_id: "exec-2", status: "failed", cleanup_status: "partial", failure_code: "scan_failed" })],
      capabilities: CAPABILITIES,
      credentialed_smoke: false,
    });
    render(<CwppSideScanPage />);
    const table = await screen.findByRole("table");
    expect(within(table).getByText("Scan complete")).toBeInTheDocument();
    expect(within(table).getByText("Failed")).toBeInTheDocument();
    // Metadata-only counts appear in the table.
    expect(within(table).getAllByText("42").length).toBeGreaterThan(0);
  });

  it("filters and paginates execution history", async () => {
    const executions = Array.from({ length: 27 }, (_, index) =>
      execution({
        execution_id: `exec-${index}`,
        provider: index === 26 ? "azure" : "gcp",
        status: index === 25 ? "failed" : "scan_complete",
      }),
    );
    apiMock.listSideScans.mockResolvedValue({
      tenant_id: "tenant-acme",
      executions,
      capabilities: CAPABILITIES,
      credentialed_smoke: false,
    });
    render(<CwppSideScanPage />);

    expect(await screen.findAllByTestId("cwpp-execution-row")).toHaveLength(25);
    expect(screen.getByText(/Page 1 of 2 \(27 executions\)/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Next/i }));
    expect(screen.getAllByTestId("cwpp-execution-row")).toHaveLength(2);

    fireEvent.change(screen.getByLabelText("Filter executions by provider"), { target: { value: "azure" } });
    expect(screen.getAllByTestId("cwpp-execution-row")).toHaveLength(1);
    expect(screen.getByText(/Page 1 of 1 \(1 executions\)/)).toBeInTheDocument();
  });

  it("shows an error state and retries on failure", async () => {
    apiMock.listSideScans.mockRejectedValueOnce(new Error("boom"));
    render(<CwppSideScanPage />);
    await waitFor(() => expect(screen.getByText("Could not load side-scans")).toBeInTheDocument());
    apiMock.listSideScans.mockResolvedValueOnce({ tenant_id: "tenant-acme", executions: [], capabilities: CAPABILITIES, credentialed_smoke: false });
    fireEvent.click(screen.getByText("Retry"));
    await waitFor(() => expect(screen.getByText("Executor capabilities")).toBeInTheDocument());
  });

  it("triggers a side-scan and surfaces the returned status", async () => {
    apiMock.listSideScans.mockResolvedValue({ tenant_id: "tenant-acme", executions: [], capabilities: CAPABILITIES, credentialed_smoke: false });
    apiMock.triggerSideScan.mockResolvedValue({ status: "scan_complete", execution_id: "exec-newrun-000000", provider: "gcp", tenant_id: "tenant-acme" });
    render(<CwppSideScanPage />);
    await waitFor(() => expect(screen.getByText("Run a side-scan")).toBeInTheDocument());

    fireEvent.change(screen.getByPlaceholderText("proj / SUB"), { target: { value: "proj-1" } });
    fireEvent.change(screen.getByPlaceholderText("projects/…/disks/os"), { target: { value: "projects/proj-1/zones/us-central1-a/disks/os" } });
    fireEvent.change(screen.getByPlaceholderText("us-central1-a"), { target: { value: "us-central1-a" } });
    fireEvent.change(screen.getByPlaceholderText("collector-vm"), { target: { value: "collector-vm" } });

    fireEvent.click(screen.getByRole("button", { name: /Run side-scan/i }));
    await waitFor(() => expect(apiMock.triggerSideScan).toHaveBeenCalledTimes(1));
    const body = apiMock.triggerSideScan.mock.calls[0]![0];
    expect(body).toMatchObject({ provider: "gcp", account_id: "proj-1", collector_id: "collector-vm" });
    // No credential field is ever sent.
    expect(body).not.toHaveProperty("secret");
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/Scan complete/));
  });

  it("shows an honest disabled envelope when side-scan is off", async () => {
    apiMock.listSideScans.mockResolvedValue({ tenant_id: "tenant-acme", executions: [], capabilities: CAPABILITIES, credentialed_smoke: false });
    apiMock.triggerSideScan.mockResolvedValue({
      status: "disabled",
      execution_id: "exec-x",
      provider: "gcp",
      tenant_id: "tenant-acme",
      enable: "Set AGENT_BOM_SIDESCAN=1 and provide a scoped snapshot role plus an in-account collector.",
    });
    render(<CwppSideScanPage />);
    await waitFor(() => expect(screen.getByText("Run a side-scan")).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText("proj / SUB"), { target: { value: "proj-1" } });
    fireEvent.change(screen.getByPlaceholderText("projects/…/disks/os"), { target: { value: "d" } });
    fireEvent.change(screen.getByPlaceholderText("us-central1-a"), { target: { value: "z" } });
    fireEvent.change(screen.getByPlaceholderText("collector-vm"), { target: { value: "c" } });
    fireEvent.click(screen.getByRole("button", { name: /Run side-scan/i }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent(/AGENT_BOM_SIDESCAN/));
  });

  it("disables the run button for non-admin roles", async () => {
    authState.capabilities = [];
    apiMock.listSideScans.mockResolvedValue({ tenant_id: "tenant-acme", executions: [], capabilities: CAPABILITIES, credentialed_smoke: false });
    render(<CwppSideScanPage />);
    await waitFor(() => expect(screen.getByText("Admin role required to run.")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /Run side-scan/i })).toBeDisabled();
  });
});
