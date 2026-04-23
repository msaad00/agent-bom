import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import SourcesPage from "@/app/sources/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listConnectors: vi.fn(),
    getConnectorHealth: vi.fn(),
    listSchedules: vi.fn(),
    listSources: vi.fn(),
    syncFleet: vi.fn(),
    createSource: vi.fn(),
    testSource: vi.fn(),
    runSource: vi.fn(),
    deleteSource: vi.fn(),
    createSchedule: vi.fn(),
    toggleSchedule: vi.fn(),
    deleteSchedule: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: {
      authenticated: true,
      auth_required: true,
      configured_modes: ["oidc"],
      recommended_ui_mode: "browser_oidc",
      auth_method: "oidc",
      subject: "user@example.com",
      tenant_id: "tenant-acme",
      role: "analyst",
      role_summary: {
        role: "analyst",
        ui_role: "contributor",
        display_name: "Contributor",
        description: "Contributor-level operator access.",
        capabilities: ["inventory.read", "scan.run", "sources.manage", "exceptions.manage", "runtime.ingest"],
        capability_matrix: [],
        can_see: ["Inventory, findings, fleet, graph, remediation, audit, and governance surfaces"],
        can_do: ["Run scans, manage sources and schedules, and create exception workflows"],
        cannot_do: ["Create, rotate, or revoke API keys"],
      },
      memberships: [],
      request_id: "req-1",
      trace_id: "trace-1",
      span_id: "span-1",
    },
    loading: false,
    error: null,
    refresh: vi.fn(),
    hasCapability: (capability: string) =>
      ["inventory.read", "scan.run", "sources.manage", "exceptions.manage", "runtime.ingest"].includes(capability),
  }),
}));

vi.mock("@/lib/api", () => ({
  api: apiMock,
}));

function primeApi() {
  apiMock.listConnectors.mockResolvedValue({ connectors: ["jira"] });
  apiMock.getConnectorHealth.mockResolvedValue({
    connector: "jira",
    state: "healthy",
    message: "ready",
  });
  apiMock.listSchedules.mockResolvedValue([
    {
      schedule_id: "sched-1",
      name: "Nightly cloud posture",
      cron_expression: "0 2 * * *",
      scan_config: { source_id: "src-1" },
      enabled: true,
      last_run: null,
      next_run: "2026-04-22T02:00:00Z",
      last_job_id: null,
      created_at: "2026-04-21T00:00:00Z",
      updated_at: "2026-04-21T00:00:00Z",
      tenant_id: "tenant-acme",
    },
  ]);
  apiMock.listSources.mockResolvedValue({
    count: 2,
    sources: [
      {
        source_id: "src-1",
        tenant_id: "tenant-acme",
        display_name: "AWS production account",
        kind: "scan.cloud",
        description: "Cloud account scan",
        owner: "platform-security",
        connector_name: "",
        credential_mode: "reference",
        credential_ref: "",
        enabled: true,
        status: "configured",
        config: {},
        created_at: "2026-04-21T00:00:00Z",
        updated_at: "2026-04-21T00:00:00Z",
        last_tested_at: null,
        last_test_status: null,
        last_test_message: null,
        last_run_at: null,
        last_run_status: null,
        last_job_id: null,
      },
      {
        source_id: "src-2",
        tenant_id: "tenant-acme",
        display_name: "Jira inventory",
        kind: "connector.cloud_read_only",
        description: "Connector-backed source",
        owner: "platform-security",
        connector_name: "jira",
        credential_mode: "reference",
        credential_ref: "",
        enabled: true,
        status: "healthy",
        config: {},
        created_at: "2026-04-21T00:00:00Z",
        updated_at: "2026-04-21T00:00:00Z",
        last_tested_at: null,
        last_test_status: null,
        last_test_message: null,
        last_run_at: null,
        last_run_status: null,
        last_job_id: null,
      },
    ],
  });
}

beforeEach(() => {
  Object.values(apiMock).forEach((mockFn) => mockFn.mockReset());
  primeApi();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SourcesPage", () => {
  it("renders linked schedule state from the control plane", async () => {
    render(<SourcesPage />);

    await waitFor(() => expect(screen.getByText("Nightly cloud posture")).toBeInTheDocument());
    expect(screen.getByText("Nightly cloud posture")).toBeInTheDocument();
    expect(screen.getByText("Source: AWS production account")).toBeInTheDocument();
    expect(screen.getByText("Schedules: 1")).toBeInTheDocument();
  });

  it("creates a schedule bound to a source_id", async () => {
    apiMock.createSchedule.mockResolvedValue({
      schedule_id: "sched-2",
      name: "Recurring AWS run",
      cron_expression: "15 * * * *",
      scan_config: { source_id: "src-1" },
      enabled: true,
      last_run: null,
      next_run: "2026-04-21T15:00:00Z",
      last_job_id: null,
      created_at: "2026-04-21T00:00:00Z",
      updated_at: "2026-04-21T00:00:00Z",
      tenant_id: "tenant-acme",
    });

    render(<SourcesPage />);

    await waitFor(() => expect(screen.getByText("Persisted schedules")).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("Schedule source"), { target: { value: "src-1" } });
    fireEvent.change(screen.getByLabelText("Schedule name"), { target: { value: "Recurring AWS run" } });
    fireEvent.change(screen.getByLabelText("Schedule cron"), { target: { value: "15 * * * *" } });
    fireEvent.click(screen.getByRole("button", { name: "Create schedule" }));

    await waitFor(() =>
      expect(apiMock.createSchedule).toHaveBeenCalledWith({
        name: "Recurring AWS run",
        cron_expression: "15 * * * *",
        enabled: true,
        scan_config: { source_id: "src-1" },
      })
    );
  });

  it("toggles and deletes schedules through the backend API", async () => {
    apiMock.toggleSchedule.mockResolvedValue({
      schedule_id: "sched-1",
      name: "Nightly cloud posture",
      cron_expression: "0 2 * * *",
      scan_config: { source_id: "src-1" },
      enabled: false,
      last_run: null,
      next_run: "2026-04-22T02:00:00Z",
      last_job_id: null,
      created_at: "2026-04-21T00:00:00Z",
      updated_at: "2026-04-21T00:00:00Z",
      tenant_id: "tenant-acme",
    });
    apiMock.deleteSchedule.mockResolvedValue(undefined);

    render(<SourcesPage />);

    await waitFor(() => expect(screen.getByText("Nightly cloud posture")).toBeInTheDocument());

    const scheduleCard = screen.getByText("Nightly cloud posture").closest("div.rounded-2xl");
    expect(scheduleCard).not.toBeNull();
    const scheduleActions = within(scheduleCard as HTMLElement);

    fireEvent.click(scheduleActions.getByRole("button", { name: "Pause" }));
    await waitFor(() => expect(apiMock.toggleSchedule).toHaveBeenCalledWith("sched-1"));

    fireEvent.click(scheduleActions.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(apiMock.deleteSchedule).toHaveBeenCalledWith("sched-1"));
  });
});
