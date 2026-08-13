import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConnectionsPage from "@/app/connections/page";

const { apiMock, navState, replaceMock, authState } = vi.hoisted(() => ({
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
  authState: {
    authRequired: true,
    authMethod: "api_key",
    managedTrialMode: false,
    managedTrialEnvelope: null as null | {
      providers: string[];
      inventory_scope: string;
      max_regions: number;
      cloud_connections: number;
      cloud_connections_per_provider: number;
      active_scan_jobs: number;
      retained_scan_jobs: number;
      scan_credits_24h: number;
      auto_scan_on_create: boolean;
      schedules: boolean;
      continuous_scans: boolean;
    },
    role: "analyst",
    capabilities: ["inventory.read", "scan.run", "sources.manage", "fleet.manage"],
  },
}));

function managedTrialEnvelope() {
  return {
    providers: ["aws"],
    inventory_scope: "account",
    max_regions: 5,
    cloud_connections: 2,
    cloud_connections_per_provider: 2,
    active_scan_jobs: 1,
    retained_scan_jobs: 20,
    scan_credits_24h: 8,
    auto_scan_on_create: false,
    schedules: false,
    continuous_scans: false,
  };
}

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
      auth_required: authState.authRequired,
      auth_method: authState.authMethod,
      managed_trial_mode: authState.managedTrialMode,
      managed_trial_envelope: authState.managedTrialEnvelope,
      tenant_id: "tenant-acme",
      role: authState.role,
    },
    loading: false,
    error: null,
    refresh: vi.fn(),
    hasCapability: (capability: string) => authState.capabilities.includes(capability),
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

const SOURCE_RECORD = {
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
  authState.authRequired = true;
  authState.authMethod = "api_key";
  authState.managedTrialMode = false;
  authState.managedTrialEnvelope = null;
  authState.role = "analyst";
  authState.capabilities = ["inventory.read", "scan.run", "sources.manage", "fleet.manage"];
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
  const TEST_OK = {
    schema_version: "cloud.connections.test.v1",
    connection_id: "conn-1",
    tenant_id: "tenant-acme",
    provider: "aws",
    status: "ok",
  };

  function fillAwsDetails(wizard: HTMLElement): string {
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    const setupId = within(wizard).getByTestId("wizard-external-id").textContent!.trim();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    fireEvent.change(within(wizard).getByPlaceholderText("Production account"), {
      target: { value: "Production account" },
    });
    fireEvent.change(within(wizard).getByPlaceholderText(/arn:aws:iam/), {
      target: { value: "arn:aws:iam::123456789012:role/agent-bom-readonly" },
    });
    fireEvent.change(within(wizard).getByPlaceholderText("us-east-1, us-west-2"), {
      target: { value: "us-east-1" },
    });
    return setupId;
  }

  it("keeps an anonymous viewer read-only when authentication is optional", async () => {
    authState.authRequired = false;
    authState.authMethod = "anonymous";
    authState.role = "viewer";
    authState.capabilities = ["inventory.read"];

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const addAccount = screen.getByRole("button", { name: "Add cloud account" });
    const connectAws = screen.getByRole("button", { name: "Connect Amazon Web Services" });
    expect(addAccount).toBeDisabled();
    expect(connectAws).toBeDisabled();
    fireEvent.click(addAccount);
    fireEvent.click(connectAws);
    expect(screen.queryByRole("dialog", { name: "Add cloud account" })).not.toBeInTheDocument();
    expect(apiMock.createCloudConnection).not.toHaveBeenCalled();
  });

  it("renders failed inventory reads as unavailable rather than factual zero", async () => {
    apiMock.listCloudConnections.mockRejectedValue(new Error("Forbidden"));
    apiMock.listSources.mockRejectedValue(new Error("Forbidden"));
    apiMock.listSchedules.mockRejectedValue(new Error("Forbidden"));

    render(<ConnectionsPage />);
    await waitForConnectTab();

    expect(screen.getAllByText("Unavailable").length).toBeGreaterThanOrEqual(3);
  });

  it("uses explicit capabilities for a self-hosted no-auth contributor", async () => {
    authState.authRequired = false;
    authState.authMethod = "anonymous";
    authState.role = "analyst";
    authState.capabilities = ["inventory.read", "scan.run", "sources.manage"];

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const addAccount = screen.getByRole("button", { name: "Add cloud account" });
    expect(addAccount).toBeEnabled();
    fireEvent.click(addAccount);
    expect(screen.getByRole("dialog", { name: "Add cloud account" })).toBeInTheDocument();
  });

  it("traps wizard focus, closes on Escape, and restores the trigger", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();
    const trigger = screen.getByRole("button", { name: "Add cloud account" });
    trigger.focus();
    fireEvent.click(trigger);

    const wizard = screen.getByRole("dialog", { name: "Add cloud account" });
    expect(wizard).toContainElement(document.activeElement as HTMLElement);
    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Add cloud account" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("limits managed-trial connect actions to the AWS account envelope", async () => {
    authState.authMethod = "managed_trial_oidc";
    authState.managedTrialMode = true;
    authState.managedTrialEnvelope = managedTrialEnvelope();
    authState.role = "analyst";
    authState.capabilities = ["inventory.read", "scan.run", "sources.manage"];

    render(<ConnectionsPage />);
    await waitForConnectTab();

    expect(screen.getByRole("button", { name: "Connect Amazon Web Services" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Connect Microsoft Azure" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Register Repositories" })).toBeDisabled();

    const wizard = openAwsWizard();
    expect(within(wizard).getByText(/0 of 2 AWS connections/i)).toBeInTheDocument();
    expect(within(wizard).getByText(/8 scans per rolling 24 hours/i)).toBeInTheDocument();
    expect(within(wizard).getByText(/one active scan and 20 retained jobs/i)).toBeInTheDocument();
    expect(within(wizard).queryByText("Whole organization")).not.toBeInTheDocument();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    expect(within(wizard).getByTestId("wizard-auto-scan-on-create")).not.toBeChecked();
    expect(within(wizard).getByTestId("wizard-auto-scan-on-create")).toBeDisabled();
    expect(within(wizard).getByTestId("wizard-scan-mode-continuous")).toBeDisabled();
    expect(within(wizard).getByTestId("wizard-all-regions")).toBeDisabled();
  });

  it("uses the server trial envelope even for an API-key principal", async () => {
    authState.authMethod = "api_key";
    authState.managedTrialMode = true;
    authState.managedTrialEnvelope = managedTrialEnvelope();
    authState.role = "admin";
    authState.capabilities = ["inventory.read", "scan.run", "sources.manage", "fleet.manage"];

    render(<ConnectionsPage />);
    await waitForConnectTab();

    expect(screen.getByRole("button", { name: "Connect Amazon Web Services" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Connect Microsoft Azure" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Register Repositories" })).toBeDisabled();
  });

  it("reconciles direct connection evidence with an older locked service registry", async () => {
    apiMock.getPostureCounts.mockResolvedValue({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0,
      kev: 0,
      compound_issues: 0,
      scan_count: 3,
      services: {
        cloud_accounts: { state: "locked", count: 0 },
        data_sources: { state: "locked", count: 0 },
      },
    });
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [
        {
          ...CREATED_RECORD,
          status: "active",
          // Noon UTC keeps the calendar date stable across every supported
          // runner timezone while still exercising the localized formatter.
          last_scan_at: "2026-06-27T12:00:00Z",
          last_scan_id: "scan-3",
        },
      ],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitForConnectTab();

    expect(screen.queryByText(/Cloud accounts is not configured yet/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/No completed scans yet/i)).not.toBeInTheDocument();
    expect(screen.getByText("Last scan")).toBeInTheDocument();
    expect(screen.getByText("Jun 27")).toBeInTheDocument();
  });

  it("carries one AWS ExternalId from setup through details into create + verify", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);
    apiMock.testCloudConnection.mockResolvedValue(TEST_OK);

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
        inventory_scope: "account",
        scan_mode: "full",
        auto_scan_on_create: false,
      }),
    );

    await waitFor(() =>
      expect(screen.getByText("Connected Production account.")).toBeInTheDocument(),
    );

    // Create advances to Verify (does not close), which auto-runs the real test.
    await waitFor(() => expect(apiMock.testCloudConnection).toHaveBeenCalledWith("conn-1"));
    expect(within(wizard).getByRole("heading", { name: "Verify connectivity" })).toBeInTheDocument();
  });

  it("verify step confirms read-only access and runs the first scan", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);
    apiMock.testCloudConnection.mockResolvedValue(TEST_OK);
    apiMock.scanCloudConnection.mockResolvedValue({
      schema_version: "cloud.connections.scan.accepted.v1",
      connection_id: "conn-1",
      tenant_id: "tenant-acme",
      provider: "aws",
      job_id: "abcdef12-3456-7890-abcd-ef1234567890",
      status: "pending",
    });

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    fillAwsDetails(wizard);
    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() => expect(apiMock.testCloudConnection).toHaveBeenCalledWith("conn-1"));
    await waitFor(() =>
      expect(within(wizard).getByText("Read-only access verified")).toBeInTheDocument(),
    );

    fireEvent.click(within(wizard).getByRole("button", { name: /Run first scan/ }));
    await waitFor(() => expect(apiMock.scanCloudConnection).toHaveBeenCalledWith("conn-1"));
    await waitFor(() =>
      expect(within(wizard).getByText(/First scan started/)).toBeInTheDocument(),
    );
  });

  it("verify step surfaces a missing-permission failure honestly (no fake green)", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);
    apiMock.testCloudConnection.mockRejectedValue(
      new Error("AccessDenied: the role is missing sts:AssumeRole for the ExternalId trust policy."),
    );

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    fillAwsDetails(wizard);
    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() => expect(apiMock.testCloudConnection).toHaveBeenCalledWith("conn-1"));
    await waitFor(() =>
      expect(within(wizard).getByText(/missing sts:AssumeRole/)).toBeInTheDocument(),
    );

    // Honest: no success state, and the first scan is NOT offered on a failed verify.
    expect(within(wizard).queryByText("Read-only access verified")).toBeNull();
    expect(within(wizard).queryByRole("button", { name: /Run first scan/ })).toBeNull();
    expect(apiMock.scanCloudConnection).not.toHaveBeenCalled();
    expect(within(wizard).getByRole("button", { name: /Retry verification/ })).toBeInTheDocument();
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

  it("offers an org-wide StackSet path on the AWS setup step (deploy once, auto-enroll)", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));

    // Single-account is the default; the CLI grant script is shown.
    expect(within(wizard).getByText(/aws iam create-role/)).toBeInTheDocument();
    const setupId = within(wizard).getByTestId("wizard-external-id").textContent!.trim();

    // Switch to the whole-organization scope.
    fireEvent.click(within(wizard).getByRole("button", { name: /Whole organization/i }));

    // The StackSet artifact is surfaced with the same ExternalId + consistent role.
    const stackSet = within(wizard).getByTestId("wizard-org-stackset");
    expect(stackSet.textContent).toContain("aws cloudformation create-stack-set");
    expect(stackSet.textContent).toContain("--auto-deployment Enabled=true");
    expect(stackSet.textContent).toContain("OrganizationalUnitIds");
    expect(stackSet.textContent).toContain("agent-bom-readonly");
    expect(stackSet.textContent).toContain(`EXTERNAL_ID=${setupId}`);

    // Honest copy: StackSet is grant onboarding; Connections org scope fans scan.
    const explainer = within(wizard).getByTestId("wizard-org-explainer").textContent ?? "";
    expect(explainer).toMatch(/every member account/i);
    expect(explainer).toMatch(/auto-enroll|automatically/i);
    expect(explainer).toMatch(/read-only/i);
    expect(explainer).toMatch(/management account|delegated admin/i);
    expect(explainer).toMatch(/inventory_scope=organization/);
    expect(explainer).toMatch(/fans out across member accounts/i);
    expect(stackSet.textContent).toMatch(/inventory_scope=organization|AGENT_BOM_AWS_ORG_INVENTORY/);
    expect(stackSet.textContent).not.toMatch(/enumerates the org and assumes/i);

    // The single-account CLI grant script is hidden while in org scope.
    expect(within(wizard).queryByText(/aws iam create-role/)).toBeNull();

    // The ExternalId still carries into Details unchanged (management-account role).
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    expect(within(wizard).getByTestId("wizard-external-id-details").textContent!.trim()).toBe(setupId);
  });

  it("create payload includes inventory_scope=organization when Whole organization selected", async () => {
    apiMock.createCloudConnection.mockResolvedValue({
      ...CREATED_RECORD,
      inventory_scope: "organization",
    });
    apiMock.testCloudConnection.mockResolvedValue({
      schema_version: "cloud.connections.test.v1",
      connection_id: "conn-1",
      tenant_id: "tenant-acme",
      provider: "aws",
      ok: true,
      detail: "ok",
    });

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));
    fireEvent.click(within(wizard).getByRole("button", { name: /Whole organization/i }));
    const setupId = within(wizard).getByTestId("wizard-external-id").textContent!.trim();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));

    fireEvent.change(within(wizard).getByPlaceholderText("Production account"), {
      target: { value: "Org production" },
    });
    fireEvent.change(within(wizard).getByPlaceholderText(/arn:aws:iam/), {
      target: { value: "arn:aws:iam::111111111111:role/agent-bom-readonly" },
    });
    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: "aws",
          display_name: "Org production",
          external_id: setupId,
          inventory_scope: "organization",
          scan_mode: "full",
          auto_scan_on_create: false,
        }),
      ),
    );
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
        inventory_scope: "account",
        scan_mode: "full",
        auto_scan_on_create: false,
      }),
    );

    await waitFor(() => expect(document.body.textContent).not.toContain(SECRET));
  });

  it("submits the all-regions sentinel when 'All enabled regions' is checked (AWS)", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);

    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    const setupId = fillAwsDetails(wizard);
    // Free-text region input is present by default; the all-regions checkbox is off.
    expect(within(wizard).getByPlaceholderText("us-east-1, us-west-2")).toBeInTheDocument();

    fireEvent.click(within(wizard).getByTestId("wizard-all-regions"));
    // Checking it hides the per-region free-text path (progressive disclosure).
    expect(within(wizard).queryByPlaceholderText("us-east-1, us-west-2")).toBeNull();

    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith(
        expect.objectContaining({ provider: "aws", external_id: setupId, regions: ["all"] }),
      ),
    );
  });

  it("defaults auto first scan off so verify precedes the explicit scan", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);
    apiMock.testCloudConnection.mockResolvedValue(TEST_OK);

    render(<ConnectionsPage />);
    await waitForConnectTab();
    const wizard = openAwsWizard();
    const setupId = fillAwsDetails(wizard);
    expect(within(wizard).getByTestId("wizard-auto-scan-on-create")).not.toBeChecked();
    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith(
        expect.objectContaining({
          auto_scan_on_create: false,
          scan_mode: "full",
          display_name: "Production account",
          external_id: setupId,
        }),
      ),
    );
  });

  it("hands off the scan-on-create job instead of queueing a duplicate first scan", async () => {
    apiMock.createCloudConnection.mockResolvedValue({
      ...CREATED_RECORD,
      auto_scan_on_create: true,
      last_scan_id: "auto-job-1",
    });
    apiMock.testCloudConnection.mockResolvedValue(TEST_OK);

    render(<ConnectionsPage />);
    await waitForConnectTab();
    const wizard = openAwsWizard();
    fillAwsDetails(wizard);
    fireEvent.click(within(wizard).getByTestId("wizard-auto-scan-on-create"));
    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() => expect(within(wizard).getByText(/First scan started/)).toBeInTheDocument());
    expect(within(wizard).queryByRole("button", { name: /Run first scan/ })).not.toBeInTheDocument();
    expect(within(wizard).getByRole("link", { name: "Track scan" })).toHaveAttribute(
      "href",
      "/scan?id=auto-job-1",
    );
    expect(apiMock.scanCloudConnection).not.toHaveBeenCalled();
  });

  it("create payload includes scan_mode=continuous when Continuous is checked", async () => {
    apiMock.createCloudConnection.mockResolvedValue({
      ...CREATED_RECORD,
      scan_mode: "continuous",
    });
    apiMock.testCloudConnection.mockResolvedValue(TEST_OK);

    render(<ConnectionsPage />);
    await waitForConnectTab();
    const wizard = openAwsWizard();
    const setupId = fillAwsDetails(wizard);

    const continuous = within(wizard).getByTestId("wizard-scan-mode-continuous");
    expect(continuous).not.toBeChecked();
    expect(within(wizard).queryByTestId("wizard-continuous-queue-hint")).toBeNull();

    fireEvent.click(continuous);
    expect(continuous).toBeChecked();
    const wizardHint = within(wizard).getByTestId("wizard-continuous-queue-hint");
    expect(wizardHint).toHaveTextContent(/event queue/i);
    expect(wizardHint).toHaveTextContent("AGENT_BOM_CONNECTIONS_SCHEDULER");

    fireEvent.click(within(wizard).getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith(
        expect.objectContaining({
          scan_mode: "continuous",
          display_name: "Production account",
          external_id: setupId,
        }),
      ),
    );
  });

  it("threads opt-in DSPM bucket ARNs into the AWS grant script, bucket-scoped", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    const wizard = openAwsWizard();
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));

    const grantScript = () => within(wizard).getByText(/aws iam create-role/).closest("pre")!;
    // Baseline: no S3 object read in the actual grant script.
    expect(grantScript().textContent).not.toContain("s3:GetObject");

    // Open the progressive-disclosure depth control and scope a DSPM bucket.
    fireEvent.click(within(wizard).getByRole("button", { name: /Scan depth/i }));
    fireEvent.change(within(wizard).getByTestId("wizard-dspm-buckets"), {
      target: { value: "arn:aws:s3:::data-lake" },
    });

    await waitFor(() => expect(grantScript().textContent).toContain("s3:GetObject"));
    expect(grantScript().textContent).toContain("arn:aws:s3:::data-lake");
  });

  it("generates the Snowflake Snowpark native-app (SPCS) recipe from the wizard", async () => {
    render(<ConnectionsPage />);
    await waitForConnectTab();

    fireEvent.click(screen.getByRole("button", { name: "Add cloud account" }));
    const wizard = screen.getByRole("dialog", { name: "Add cloud account" });
    fireEvent.click(within(wizard).getByRole("button", { name: /Snowflake/ }));
    fireEvent.click(within(wizard).getByRole("button", { name: /Next/ }));

    // Default packaging is the read-only role; switch to the native app.
    fireEvent.click(within(wizard).getByRole("button", { name: /Native app \(SPCS\)/i }));

    const recipe = within(wizard).getByTestId("wizard-snowflake-spcs").textContent ?? "";
    expect(recipe).toContain("snow app run --project deploy/snowflake/native-app");
    expect(recipe).toContain("Next step:");
    expect(recipe).toContain("deploy/snowflake/native-app");
    expect(recipe.toLowerCase()).toContain("read-only");
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
    expect(within(drawer).getByText(/79 MCP tools/)).toBeInTheDocument();
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

  it("queues a durable read-only scan and links to its job", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [{ ...CREATED_RECORD, status: "active" }],
      count: 1,
    });
    apiMock.scanCloudConnection.mockResolvedValue({
      schema_version: "cloud.connections.scan.accepted.v1",
      connection_id: "conn-1",
      tenant_id: "tenant-acme",
      provider: "aws",
      job_id: "abcdef12-3456-7890-abcd-ef1234567890",
      status: "pending",
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
    await waitFor(() => expect(apiMock.scanCloudConnection).toHaveBeenCalledWith("conn-1"));

    fireEvent.click(screen.getByRole("button", { name: "Production account" }));
    const drawer = await screen.findByRole("dialog", { name: "Production account" });
    await waitFor(() => expect(within(drawer).getByText("Read-only scan queued")).toBeInTheDocument());
    expect(within(drawer).getByRole("link", { name: "Scan result" })).toHaveAttribute(
      "href",
      "/scan?id=abcdef12-3456-7890-abcd-ef1234567890",
    );
    expect(within(drawer).getByRole("link", { name: "Jobs" })).toHaveAttribute(
      "href",
      "/jobs?q=abcdef12-3456-7890-abcd-ef1234567890",
    );
  });

  it("shows the accepted Azure job without exposing provider evidence records", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [{ ...CREATED_RECORD, provider: "azure", status: "active" }],
      count: 1,
    });
    apiMock.scanCloudConnection.mockResolvedValue({
      schema_version: "cloud.connections.scan.accepted.v1",
      connection_id: "conn-1",
      tenant_id: "tenant-acme",
      provider: "azure",
      job_id: "azure-scan-1",
      status: "pending",
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Run scan" }));
    await waitFor(() => expect(apiMock.scanCloudConnection).toHaveBeenCalledWith("conn-1"));
    fireEvent.click(screen.getByRole("button", { name: "Production account" }));

    const drawer = await screen.findByRole("dialog", { name: "Production account" });
    expect(within(drawer).getByText("Read-only scan queued")).toBeInTheDocument();
    expect(within(drawer).queryByText(/binding|diagnostic/i)).not.toBeInTheDocument();
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

  it("requires verification before a connection scan", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    expect(screen.getByRole("button", { name: "Run scan" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Production account" }));
    expect(within(await screen.findByRole("dialog", { name: "Production account" })).getByRole("button", { name: "Run scan" })).toBeDisabled();
  });

  it("disables trial update and delete controls that are outside the route allowlist", async () => {
    authState.managedTrialMode = true;
    authState.authMethod = "api_key";
    authState.role = "admin";
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [{ ...CREATED_RECORD, status: "active" }],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    expect(screen.getByLabelText("Scan schedule")).toBeDisabled();
    expect(screen.getByTestId("schedule-scan-mode-continuous")).toBeDisabled();
    expect(screen.getByRole("button", { name: /Delete Production account/ })).toBeDisabled();
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
      connections_scheduler_enabled: true,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    expect(screen.getByText("Event-driven")).toBeInTheDocument();
    expect(screen.queryByText("Scheduled scan")).toBeNull();
  });

  it("shows Organization, Continuous, and Event-driven chips when state warrants", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [
        {
          ...CREATED_RECORD,
          status: "active",
          inventory_scope: "organization",
          scan_mode: "continuous",
          last_event_at: "2026-06-27T01:30:00Z",
          scan_interval_minutes: 60,
        },
      ],
      count: 1,
      connections_scheduler_enabled: true,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    expect(screen.getByTestId("connection-org-scope-chip")).toHaveTextContent("Organization");
    expect(screen.getByTestId("connection-continuous-chip")).toHaveTextContent("Continuous");
    expect(screen.getByTestId("connection-event-driven-chip")).toHaveTextContent("Event-driven");
  });

  it("does not claim Organization scope when only auth_params carries the legacy scope", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [
        {
          ...CREATED_RECORD,
          status: "active",
          inventory_scope: "account",
          auth_params: { inventory_scope: "organization" },
        },
      ],
      count: 1,
      connections_scheduler_enabled: true,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    expect(screen.queryByTestId("connection-org-scope-chip")).toBeNull();
  });

  it("shows a scheduler-disabled banner when intervals are set but the scheduler is off", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [{ ...CREATED_RECORD, status: "active", scan_interval_minutes: 60 }],
      count: 1,
      connections_scheduler_enabled: false,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    const banner = screen.getByTestId("connections-scheduler-disabled-banner");
    expect(banner).toHaveTextContent("Scheduler disabled on this control plane");
    expect(banner).toHaveTextContent("AGENT_BOM_CONNECTIONS_SCHEDULER");
  });

  it("shows the scheduler-disabled banner for continuous connections with no interval", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [
        {
          ...CREATED_RECORD,
          status: "active",
          scan_mode: "continuous",
          scan_interval_minutes: null,
        },
      ],
      count: 1,
      connections_scheduler_enabled: false,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    const banner = screen.getByTestId("connections-scheduler-disabled-banner");
    expect(banner).toHaveTextContent("AGENT_BOM_CONNECTIONS_SCHEDULER");
    expect(banner).toHaveTextContent(/continuous/i);
  });

  it("does not show the scheduler banner when the scheduler is enabled", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [{ ...CREATED_RECORD, status: "active", scan_interval_minutes: 60 }],
      count: 1,
      connections_scheduler_enabled: true,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());
    expect(screen.queryByTestId("connections-scheduler-disabled-banner")).toBeNull();
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

  it("patches scan_mode from the schedule Continuous checkbox", async () => {
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [{ ...CREATED_RECORD, status: "active", scan_interval_minutes: 60 }],
      count: 1,
      connections_scheduler_enabled: true,
    });
    apiMock.updateCloudConnection.mockResolvedValue({
      ...CREATED_RECORD,
      status: "active",
      scan_interval_minutes: 60,
      scan_mode: "continuous",
      updated_at: "2026-06-27T02:00:00Z",
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());

    const continuous = screen.getByTestId("schedule-scan-mode-continuous");
    expect(continuous).not.toBeChecked();
    expect(screen.queryByTestId("schedule-continuous-queue-hint")).toBeNull();

    fireEvent.click(continuous);

    await waitFor(() =>
      expect(apiMock.updateCloudConnection).toHaveBeenCalledWith("conn-1", {
        scan_mode: "continuous",
      }),
    );
    await waitFor(() =>
      expect(screen.getByText("Production account scan mode updated.")).toBeInTheDocument(),
    );
    const scheduleHint = screen.getByTestId("schedule-continuous-queue-hint");
    expect(scheduleHint).toHaveTextContent(/event queue/i);
    expect(scheduleHint).toHaveTextContent("AGENT_BOM_CONNECTIONS_SCHEDULER");
  });

  it("deletes a connection through the API", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
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

  it("requires confirmation before deleting a connection", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    apiMock.listCloudConnections.mockResolvedValue({
      schema_version: "cloud.connections.v1",
      tenant_id: "tenant-acme",
      connections: [CREATED_RECORD],
      count: 1,
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Production account")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Delete Production account/ }));
    expect(apiMock.deleteCloudConnection).not.toHaveBeenCalled();
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
    expect(screen.getByRole("button", { name: "Run now" })).toBeEnabled();
    const deleteButton = screen.getByRole("button", { name: "Delete" });
    expect(deleteButton).toBeDisabled();
    fireEvent.click(deleteButton);
    expect(apiMock.deleteSource).not.toHaveBeenCalled();
  });

  it("enables source deletion only for an Admin", async () => {
    authState.role = "admin";
    authState.capabilities = ["inventory.read", "scan.run", "sources.manage", "keys.manage"];
    apiMock.listSources.mockResolvedValue({
      schema_version: "sources.v1",
      tenant_id: "tenant-acme",
      count: 1,
      sources: [SOURCE_RECORD],
    });

    render(<ConnectionsPage />);
    await waitFor(() => expect(screen.getByText("Payments monorepo")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Payments monorepo" }));
    expect(screen.getByRole("button", { name: "Delete" })).toBeEnabled();
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
