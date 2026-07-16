import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConnectionsPage from "@/app/connections/page";

const { apiMock, navState, replaceMock } = vi.hoisted(() => ({
  apiMock: {
    health: vi.fn(),
    listCloudConnections: vi.fn(),
    getCloudConnection: vi.fn(),
    createCloudConnection: vi.fn(),
    updateCloudConnection: vi.fn(),
    deleteCloudConnection: vi.fn(),
    testCloudConnection: vi.fn(),
    scanCloudConnection: vi.fn(),
    getPostureCounts: vi.fn(),
    listSources: vi.fn(),
    listConnectors: vi.fn(),
    getConnectorHealth: vi.fn(),
    listSchedules: vi.fn(),
    listDiscoveryProviders: vi.fn(),
    syncFleet: vi.fn(),
    createSource: vi.fn(),
    testSource: vi.fn(),
    runSource: vi.fn(),
    deleteSource: vi.fn(),
    createSchedule: vi.fn(),
    toggleSchedule: vi.fn(),
    deleteSchedule: vi.fn(),
  },
  navState: { search: "" },
  replaceMock: vi.fn(),
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    ...rest
  }: {
    href: string;
    children: React.ReactNode;
  } & React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock }),
  useSearchParams: () => new URLSearchParams(navState.search),
}));

vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: {
      authenticated: true,
      auth_required: true,
      tenant_id: "tenant-acme",
      role: "analyst",
    },
    loading: false,
    error: null,
    refresh: vi.fn(),
    hasCapability: (capability: string) =>
      ["inventory.read", "scan.run", "sources.manage", "fleet.manage"].includes(capability),
  }),
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

const SECRET = "super-secret-external-id-value";

const CREATED_RECORD = {
  id: "conn-1",
  tenant_id: "tenant-acme",
  provider: "aws",
  display_name: "Production account",
  role_ref: "arn:aws:iam::123456789012:role/agent-bom-readonly",
  has_external_id: true,
  regions: ["us-east-1"],
  status: "pending",
  status_detail: "",
  created_at: "2026-06-27T00:00:00Z",
  updated_at: "2026-06-27T00:00:00Z",
  last_scan_at: null,
  last_event_at: null,
  last_scan_id: null,
  scan_interval_minutes: null,
};

function primeSourceApis() {
  apiMock.health.mockResolvedValue({
    status: "ok",
    version: "0.0.0-test",
    auth_required: true,
    auth_configured: true,
    configured_auth_modes: ["oidc"],
    unauthenticated_allowed: false,
  });
  apiMock.listConnectors.mockResolvedValue({ connectors: [] });
  apiMock.listSchedules.mockResolvedValue([]);
  apiMock.listDiscoveryProviders.mockResolvedValue({
    contract_version: "1",
    entrypoints_enabled: false,
    provider_count: 0,
    warnings: [],
    providers: [],
  });
  apiMock.getConnectorHealth.mockResolvedValue({ connector: "x", state: "healthy", message: "ready" });
}

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  navState.search = "";
  replaceMock.mockReset();
  apiMock.getPostureCounts.mockResolvedValue({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    total: 0,
    kev: 0,
    compound_issues: 0,
    services: {
      cloud_accounts: { state: "locked", count: 0 },
      data_sources: { state: "locked", count: 0 },
    },
  });
  apiMock.listCloudConnections.mockResolvedValue({
    schema_version: "cloud.connections.v1",
    tenant_id: "tenant-acme",
    connections: [],
    count: 0,
  });
  apiMock.listSources.mockResolvedValue({
    schema_version: "sources.v1",
    tenant_id: "tenant-acme",
    sources: [],
    count: 0,
  });
  primeSourceApis();
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function waitForConnectTab() {
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Connect Amazon Web Services" })).toBeInTheDocument(),
  );
}

function openAwsWizard(): HTMLElement {
  fireEvent.click(screen.getByRole("button", { name: "Add cloud account" }));
  return screen.getByRole("dialog", { name: "Add cloud account" });
}

describe("ConnectionsPage — Connect segment", () => {
  it("carries one AWS ExternalId from setup through details into create", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();

    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    const setupId = within(wizard).getByTestId("wizard-external-id").textContent!.trim();
    expect(setupId).toMatch(/^[a-f0-9]{32}$/);
    expect(within(wizard).getByText(/EXTERNAL_ID=/)).toBeInTheDocument();

    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    expect(screen.queryByText("A display name is required.")).toBeNull();
    expect(apiMock.createCloudConnection).not.toHaveBeenCalled();

    const detailsId = within(wizard).getByTestId("wizard-external-id-details").textContent!.trim();
    expect(detailsId).toBe(setupId);

    fireEvent.change(within(wizard).getByPlaceholderText("Production account"), {
      target: { value: "Production account" },
    });
    fireEvent.change(within(wizard).getByPlaceholderText(/arn:aws:iam/), {
      target: { value: "arn:aws:iam::123456789012:role/agent-bom-readonly" },
    });
    fireEvent.change(within(wizard).getByPlaceholderText("us-east-1, us-west-2"), {
      target: { value: "us-east-1" },
    });

    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith({
        provider: "aws",
        display_name: "Production account",
        role_ref: "arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id: setupId,
        regions: ["us-east-1"],
        auth_params: {},
      }),
    );

    await waitFor(() =>
      expect(screen.getByText("Connected Production account.")).toBeInTheDocument(),
    );
  });

  it("regenerating the AWS ExternalId updates setup and details together", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));

    const firstId = within(wizard).getByTestId("wizard-external-id").textContent!.trim();

    fireEvent.click(within(wizard).getByRole("button", { name: "Regenerate" }));
    const regeneratedId = within(wizard).getByTestId("wizard-external-id").textContent!.trim();
    expect(regeneratedId).toMatch(/^[a-f0-9]{32}$/);
    expect(regeneratedId).not.toBe(firstId);

    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    expect(within(wizard).getByTestId("wizard-external-id-details").textContent!.trim()).toBe(regeneratedId);
  });

  it("maps provider-specific GCP fields to role_ref / external_id / auth_params", async () => {
    apiMock.createCloudConnection.mockResolvedValue({ ...CREATED_RECORD, provider: "gcp" });

    render(<ConnectionsPage />);
    await waitForConnectTab();

    fireEvent.click(screen.getByRole("button", { name: "Add cloud account" }));
    const wizard = screen.getByRole("dialog", { name: "Add cloud account" });
    fireEvent.click(within(wizard).getByRole("button", { name: /Google Cloud/ }));
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));

    fireEvent.change(screen.getByPlaceholderText("Production account"), {
      target: { value: "GCP prod" },
    });
    fireEvent.change(screen.getByPlaceholderText(/gserviceaccount\.com/), {
      target: { value: "agent-bom@proj.iam.gserviceaccount.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("my-project-123"), {
      target: { value: "proj-123" },
    });
    const keyInput = screen.getByPlaceholderText("Paste the service-account key JSON") as HTMLTextAreaElement;
    fireEvent.change(keyInput, { target: { value: SECRET } });

    fireEvent.click(screen.getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith({
        provider: "gcp",
        display_name: "GCP prod",
        role_ref: "agent-bom@proj.iam.gserviceaccount.com",
        external_id: SECRET,
        regions: [],
        auth_params: { project_id: "proj-123" },
      }),
    );

    await waitFor(() => expect(document.body.textContent).not.toContain(SECRET));
  });

  it("renders a category-spanning connector gallery with cloud, code, AI, and data tiles", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    // Non-cloud surfaces register in-hub (a button that jumps to the Sources tab).
    expect(screen.getByRole("button", { name: "Register Repositories" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register Warehouse & lake" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Set up coding agent" })).toBeInTheDocument();
  });

  it("register jumps to the Sources segment (URL-synced)", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    fireEvent.click(screen.getByRole("button", { name: "Register Repositories" }));
    expect(replaceMock).toHaveBeenCalledWith("/connections?tab=sources");
  });

  it("filters the gallery by category and free-text search", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    fireEvent.click(screen.getByRole("tab", { name: /^Data/ }));
    expect(screen.queryByRole("button", { name: "Connect Amazon Web Services" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Register Warehouse & lake" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /^All/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search connectors" }), {
      target: { value: "kubernetes" },
    });
    expect(screen.getByRole("button", { name: "Register IaC & clusters" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect Amazon Web Services" })).not.toBeInTheDocument();
  });

  it("opens the read-only coding-agent onboarding drawer with the MCP server snippet", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    fireEvent.click(screen.getByRole("button", { name: "Set up coding agent" }));

    const drawer = await screen.findByRole("dialog", { name: /Connect a coding agent/ });
    expect(within(drawer).getByText("agent-bom mcp-server")).toBeInTheDocument();
    expect(within(drawer).getByText(/73 MCP tools/)).toBeInTheDocument();
  });

  it("syncs the segmented tab to the URL", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    fireEvent.click(screen.getByRole("tab", { name: /Sources/ }));
    expect(replaceMock).toHaveBeenCalledWith("/connections?tab=sources");
  });
});

describe("ConnectionsPage — Sources segment (unified table)", () => {
  beforeEach(() => {
    navState.search = "tab=sources";
  });

  it("runs a read-only scan and shows inventory counts + CIS pass rate", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });
    apiMock.scanCloudConnection.mockResolvedValue({
      schema_version: "cloud.connections.scan.v1",
      connection_id: "conn-1",
      tenant_id: "tenant-acme",
      provider: "aws",
      scan_id: "abcdef12-3456-7890-abcd-ef1234567890",
      inventory: {
        provider: "aws",
        account: "123456789012",
        region: "us-east-1",
        resource_count: 42,
        identity_count: 7,
        node_summary: { buckets: 3, instances: 5, security_groups: 4, roles: 6, users: 1 },
        warnings: [],
      },
      cis_benchmark: {
        benchmark: "CIS AWS",
        benchmark_version: "1.5",
        passed: 30,
        failed: 10,
        total: 40,
        pass_rate: 0.75,
      },
      audit_metadata: { read_only: true, writes_performed: false, note: "Read-only scan." },
      connection: {
        ...CREATED_RECORD,
        status: "active",
        last_scan_at: "2026-06-27T01:00:00Z",
        last_scan_id: "abcdef12-3456-7890-abcd-ef1234567890",
      },
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
    await waitFor(() => expect(apiMock.scanCloudConnection).toHaveBeenCalledWith("conn-1"));

    fireEvent.click(screen.getByRole("button", { name: "Production account" }));
    const drawer = await screen.findByRole("dialog", { name: "Production account" });
    await waitFor(() => expect(within(drawer).getByText("Read-only scan complete")).toBeInTheDocument());

    expect(within(drawer).getByText("42")).toBeInTheDocument();
    expect(within(drawer).getByText("7")).toBeInTheDocument();
    expect(within(drawer).getByText("30/40")).toBeInTheDocument();
    expect(within(drawer).getByText("75%")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: "Scan result" })).toHaveAttribute(
      "href",
      "/scan?id=abcdef12-3456-7890-abcd-ef1234567890",
    );
    expect(within(drawer).getByRole("link", { name: "Findings" })).toHaveAttribute(
      "href",
      "/findings?scan=abcdef12-3456-7890-abcd-ef1234567890",
    );
    expect(within(drawer).getByRole("link", { name: "Graph" })).toHaveAttribute(
      "href",
      "/graph?scan_id=abcdef12-3456-7890-abcd-ef1234567890",
    );
  });

  it("keeps one direct scan action in the connection drawer", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Production account" }));
    const drawer = await screen.findByRole("dialog", { name: "Production account" });
    expect(within(drawer).queryByRole("link", { name: "New Scan" })).not.toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: "Run scan" })).toBeInTheDocument();
  });

  it("tests a brokered credential without launching a scan", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });
    apiMock.testCloudConnection.mockResolvedValue({
      schema_version: "cloud.connections.test.v1",
      connection_id: "conn-1",
      tenant_id: "tenant-acme",
      provider: "aws",
      status: "ok",
      audit_metadata: {
        read_only: true,
        writes_performed: false,
        note: "Connection test brokered a read-only credential only.",
      },
      connection: { ...CREATED_RECORD, status: "active" },
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Test" }));
    await waitFor(() => expect(apiMock.testCloudConnection).toHaveBeenCalledWith("conn-1"));
    expect(apiMock.scanCloudConnection).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByText("Production account read-only credential verified.")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Production account" }));
    const drawer = await screen.findByRole("dialog", { name: "Production account" });
    expect(within(drawer).getByText(/No inventory, CIS, findings, or resource writes ran/)).toBeInTheDocument();
  });

  it("shows durable handoff links from the persisted last scan id after reload", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [
        { ...CREATED_RECORD, status: "active", last_scan_at: "2026-06-27T01:00:00Z", last_scan_id: "persisted-scan-123" },
      ],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Production account" }));
    const drawer = await screen.findByRole("dialog", { name: "Production account" });
    expect(within(drawer).getByText("Last scan handoff")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: "Scan result" })).toHaveAttribute(
      "href",
      "/scan?id=persisted-scan-123",
    );
    expect(within(drawer).getByRole("link", { name: "Jobs" })).toHaveAttribute("href", "/jobs?q=persisted-scan-123");
  });

  it("surfaces event-driven freshness when a connection has processed cloud events", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [
        { ...CREATED_RECORD, status: "active", last_event_at: "2026-06-27T01:30:00Z", scan_interval_minutes: 60 },
      ],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    expect(screen.getByText("Event-driven")).toBeInTheDocument();
    expect(screen.queryByText("Scheduled scan")).toBeNull();
  });

  it("updates the recurring scan schedule without exposing secrets", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });
    apiMock.updateCloudConnection.mockResolvedValue({
      ...CREATED_RECORD,
      scan_interval_minutes: 60,
      updated_at: "2026-06-27T02:00:00Z",
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("Scan schedule"), { target: { value: "60" } });

    await waitFor(() =>
      expect(apiMock.updateCloudConnection).toHaveBeenCalledWith("conn-1", { scan_interval_minutes: 60 }),
    );
    await waitFor(() =>
      expect(screen.getByText("Production account scan schedule updated.")).toBeInTheDocument(),
    );
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("deletes a connection through the API", async () => {
    apiMock.listCloudConnections
      .mockResolvedValueOnce({
        schema_version: "cloud.connections.v1",
        tenant_id: "tenant-acme",
        connections: [CREATED_RECORD],
        count: 1,
      })
      .mockResolvedValue({
        schema_version: "cloud.connections.v1",
        tenant_id: "tenant-acme",
        connections: [],
        count: 0,
      });
    apiMock.deleteCloudConnection.mockResolvedValue(undefined);

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /Delete Production account/ }));
    await waitFor(() => expect(apiMock.deleteCloudConnection).toHaveBeenCalledWith("conn-1"));
    await waitFor(() => expect(screen.getByText("No sources connected yet")).toBeInTheDocument());
  });

  it("merges registered sources into the unified table and opens a source drawer with evidence", async () => {
    apiMock.listSources.mockResolvedValue({
      schema_version: "sources.v1",
      tenant_id: "tenant-acme",
      count: 1,
      sources: [
        {
          source_id: "src-1",
          tenant_id: "tenant-acme",
          display_name: "Payments monorepo",
          kind: "scan.repo",
          description: "SCA scan",
          owner: "platform-security",
          connector_name: "",
          credential_mode: "none",
          credential_ref: "",
          enabled: true,
          status: "configured",
          config: {},
          last_tested_at: null,
          last_test_status: null,
          last_test_message: null,
          last_run_at: "2026-06-26T02:00:00Z",
          last_run_status: "done",
          last_job_id: "job-repo-1",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Payments monorepo")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Payments monorepo" }));
    const detail = within(await screen.findByTestId("source-detail-src-1"));
    expect(detail.getByText("Evidence workflow")).toBeInTheDocument();
    expect(detail.getByRole("link", { name: "Findings" })).toHaveAttribute("href", "/findings?scan=job-repo-1");
  });

  it("dedupes a cloud account registered as both a connection and a cloud-kind source", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });
    apiMock.listSources.mockResolvedValue({
      schema_version: "sources.v1",
      tenant_id: "tenant-acme",
      count: 1,
      sources: [
        {
          source_id: "src-dup",
          tenant_id: "tenant-acme",
          display_name: "Production account",
          kind: "scan.cloud",
          description: "",
          owner: "",
          connector_name: "",
          credential_mode: "none",
          credential_ref: "",
          enabled: true,
          status: "configured",
          config: {},
          last_tested_at: null,
          last_test_status: null,
          last_test_message: null,
          last_run_at: null,
          last_run_status: null,
          last_job_id: null,
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    // Exactly one row for the account — the cloud connection wins the dedup, so
    // the schedule <select> (cloud-only affordance) is present and unique.
    expect(screen.getAllByText("Production account")).toHaveLength(1);
    expect(screen.getByLabelText("Scan schedule")).toBeInTheDocument();
  });

  it("filters the unified table by status", async () => {
    apiMock.listSources.mockResolvedValue({
      schema_version: "sources.v1",
      tenant_id: "tenant-acme",
      count: 2,
      sources: [
        {
          source_id: "src-a",
          tenant_id: "tenant-acme",
          display_name: "Healthy repo",
          kind: "scan.repo",
          description: "",
          owner: "",
          connector_name: "",
          credential_mode: "none",
          credential_ref: "",
          enabled: true,
          status: "healthy",
          config: {},
          last_tested_at: null,
          last_test_status: null,
          last_test_message: null,
          last_run_at: null,
          last_run_status: null,
          last_job_id: null,
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
        {
          source_id: "src-b",
          tenant_id: "tenant-acme",
          display_name: "Degraded lake",
          kind: "connector.warehouse",
          description: "",
          owner: "",
          connector_name: "snow",
          credential_mode: "reference",
          credential_ref: "",
          enabled: true,
          status: "degraded",
          config: {},
          last_tested_at: null,
          last_test_status: null,
          last_test_message: null,
          last_run_at: null,
          last_run_status: null,
          last_job_id: null,
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Healthy repo")).toBeInTheDocument());
    expect(screen.getByText("Degraded lake")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "degraded" } });
    expect(screen.queryByText("Healthy repo")).not.toBeInTheDocument();
    expect(screen.getByText("Degraded lake")).toBeInTheDocument();
  });
});
