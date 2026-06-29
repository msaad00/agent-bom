import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ConnectionsPage from "@/app/connections/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listCloudConnections: vi.fn(),
    getCloudConnection: vi.fn(),
    createCloudConnection: vi.fn(),
    updateCloudConnection: vi.fn(),
    deleteCloudConnection: vi.fn(),
    scanCloudConnection: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
  }: {
    href: string;
    children: React.ReactNode;
  }) => <a href={href}>{children}</a>,
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
      ["inventory.read", "scan.run"].includes(capability),
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
  scan_interval_minutes: null,
};

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  apiMock.listCloudConnections.mockResolvedValue({
    schema_version: "cloud.connections.v1",
    tenant_id: "tenant-acme",
    connections: [],
    count: 0,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ConnectionsPage", () => {
  it("creates a connection through the wizard and lists it with has_external_id, never rendering the secret", async () => {
    apiMock.createCloudConnection.mockResolvedValue(CREATED_RECORD);
    // After create, the list refresh returns the new connection.
    apiMock.listCloudConnections
      .mockResolvedValueOnce({
        schema_version: "cloud.connections.v1",
        tenant_id: "tenant-acme",
        connections: [],
        count: 0,
      })
      .mockResolvedValue({
        schema_version: "cloud.connections.v1",
        tenant_id: "tenant-acme",
        connections: [CREATED_RECORD],
        count: 1,
      });

    render(<ConnectionsPage />);

    await waitFor(() =>
      expect(
        screen.getByText("No cloud accounts connected"),
      ).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Add cloud account" }));
    // Step 0 -> 1 -> 2. Advancing must NOT trigger a premature form submit.
    fireEvent.click(screen.getByRole("button", { name: /Next/ }));
    fireEvent.click(screen.getByRole("button", { name: /Next/ }));
    expect(screen.queryByText("A display name is required.")).toBeNull();
    expect(apiMock.createCloudConnection).not.toHaveBeenCalled();

    fireEvent.change(screen.getByPlaceholderText("Production account"), {
      target: { value: "Production account" },
    });
    fireEvent.change(screen.getByPlaceholderText(/arn:aws:iam/), {
      target: { value: "arn:aws:iam::123456789012:role/agent-bom-readonly" },
    });
    const secretInput = screen.getByPlaceholderText(
      "••••••••••••",
    ) as HTMLInputElement;
    expect(secretInput.type).toBe("password");
    fireEvent.change(secretInput, { target: { value: SECRET } });
    fireEvent.change(screen.getByPlaceholderText("us-east-1, us-west-2"), {
      target: { value: "us-east-1" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Create connection" }));

    await waitFor(() =>
      expect(apiMock.createCloudConnection).toHaveBeenCalledWith({
        provider: "aws",
        display_name: "Production account",
        role_ref: "arn:aws:iam::123456789012:role/agent-bom-readonly",
        external_id: SECRET,
        regions: ["us-east-1"],
        // AWS has no provider-specific params, so auth_params is an empty map.
        auth_params: {},
      }),
    );

    // New connection shows up in the list with the "secret configured" affordance.
    await waitFor(() =>
      expect(screen.getByText("Production account")).toBeInTheDocument(),
    );
    expect(screen.getByText("Secret configured")).toBeInTheDocument();

    // The plaintext secret must not be present anywhere in the rendered DOM.
    expect(document.body.textContent).not.toContain(SECRET);
    expect(document.querySelector(`input[value="${SECRET}"]`)).toBeNull();
  });

  it("maps provider-specific GCP fields to role_ref / external_id / auth_params", async () => {
    apiMock.createCloudConnection.mockResolvedValue({
      ...CREATED_RECORD,
      provider: "gcp",
    });

    render(<ConnectionsPage />);

    await waitFor(() =>
      expect(
        screen.getByText("No cloud accounts connected"),
      ).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Add cloud account" }));
    // Step 0: choose GCP, then advance to the details step.
    fireEvent.click(screen.getByRole("button", { name: /Google Cloud/ }));
    fireEvent.click(screen.getByRole("button", { name: /Next/ }));
    fireEvent.click(screen.getByRole("button", { name: /Next/ }));

    fireEvent.change(screen.getByPlaceholderText("Production account"), {
      target: { value: "GCP prod" },
    });
    fireEvent.change(screen.getByPlaceholderText(/gserviceaccount\.com/), {
      target: { value: "agent-bom@proj.iam.gserviceaccount.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("my-project-123"), {
      target: { value: "proj-123" },
    });
    const keyInput = screen.getByPlaceholderText(
      "Paste the service-account key JSON",
    ) as HTMLTextAreaElement;
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
        node_summary: {
          buckets: 3,
          instances: 5,
          security_groups: 4,
          roles: 6,
          users: 1,
        },
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
      audit_metadata: {
        read_only: true,
        writes_performed: false,
        note: "Read-only scan.",
      },
      connection: {
        ...CREATED_RECORD,
        status: "active",
        last_scan_at: "2026-06-27T01:00:00Z",
      },
    });

    render(<ConnectionsPage />);

    await waitFor(() =>
      expect(screen.getByText("Production account")).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Test and scan" }));

    await waitFor(() =>
      expect(apiMock.scanCloudConnection).toHaveBeenCalledWith("conn-1"),
    );
    await waitFor(() =>
      expect(screen.getByText("Read-only scan complete")).toBeInTheDocument(),
    );

    expect(screen.getByText("42")).toBeInTheDocument(); // resources
    expect(screen.getByText("7")).toBeInTheDocument(); // identities
    expect(screen.getByText("30/40")).toBeInTheDocument(); // CIS passed
    expect(screen.getByText("75%")).toBeInTheDocument(); // pass rate
    expect(screen.getByRole("link", { name: "Scan result" })).toHaveAttribute(
      "href",
      "/scan?id=abcdef12-3456-7890-abcd-ef1234567890",
    );
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute(
      "href",
      "/vulns?scan=abcdef12-3456-7890-abcd-ef1234567890",
    );
    expect(screen.getByRole("link", { name: "Graph" })).toHaveAttribute(
      "href",
      "/graph?scan_id=abcdef12-3456-7890-abcd-ef1234567890",
    );
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

    await waitFor(() =>
      expect(screen.getByText("Production account")).toBeInTheDocument(),
    );

    fireEvent.change(
      screen.getByLabelText(
        "Recurring scan schedule for Production account",
      ),
      { target: { value: "60" } },
    );

    await waitFor(() =>
      expect(apiMock.updateCloudConnection).toHaveBeenCalledWith("conn-1", {
        scan_interval_minutes: 60,
      }),
    );
    await waitFor(() => expect(screen.getByText("Runs every 1h")).toBeInTheDocument());
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

    await waitFor(() =>
      expect(screen.getByText("Production account")).toBeInTheDocument(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: /Delete Production account/ }),
    );
    await waitFor(() =>
      expect(apiMock.deleteCloudConnection).toHaveBeenCalledWith("conn-1"),
    );
    await waitFor(() =>
      expect(
        screen.getByText("No cloud accounts connected"),
      ).toBeInTheDocument(),
    );
  });
});
