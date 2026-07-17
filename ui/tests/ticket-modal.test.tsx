import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  TicketModal,
  findingKey,
  buildFinding,
} from "@/components/ticket-modal";
import type { RemediationItem, TicketLink } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listTicketingConnections: vi.fn(),
    createTicket: vi.fn(),
    syncTicket: vi.fn(),
    listTickets: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    className,
  }: {
    href: string;
    children: React.ReactNode;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

const ITEM: RemediationItem = {
  package: "requests",
  ecosystem: "pypi",
  current_version: "2.0.0",
  fixed_version: "2.31.0",
  severity: "critical",
  is_kev: false,
  impact_score: 8.4,
  vulnerabilities: ["CVE-2024-1234"],
  affected_agents: ["agent-a"],
  agents_pct: 50,
  exposed_credentials: [],
  credentials_pct: 0,
  reachable_tools: [],
  tools_pct: 0,
  owasp_tags: [],
  atlas_tags: [],
  risk_narrative: "",
};

const ACTIVE_CONN = {
  id: "conn-1",
  tenant_id: "t1",
  provider: "jira",
  transport: "mcp",
  auth_method: "mcp",
  display_name: "Prod Jira",
  endpoint: "https://itsm.example.com",
  auth_params: { default_project: "SEC" },
  status: "active",
  status_detail: "",
  created_at: "",
  updated_at: "",
  has_secret: true,
};

function connectionsResp(connections: unknown[]) {
  return {
    schema_version: "ticketing.connections.v1",
    tenant_id: "t1",
    connections,
    count: connections.length,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("TicketModal", () => {
  it("no active connection → guides to Connections, never a credential field", async () => {
    apiMock.listTicketingConnections.mockResolvedValue(connectionsResp([]));

    render(
      <TicketModal item={ITEM} existingTickets={[]} onClose={() => {}} />,
    );

    await waitFor(() =>
      expect(screen.getByText(/configured once in/i)).toBeInTheDocument(),
    );
    const link = screen.getByRole("link", { name: /Open Connections/i });
    expect(link).toHaveAttribute("href", "/connections");
    // No credential/token/URL inputs anywhere.
    expect(screen.queryByPlaceholderText(/token/i)).toBeNull();
    expect(document.querySelector('input[type="password"]')).toBeNull();
    expect(
      screen.queryByRole("button", { name: /Create ticket/i }),
    ).toBeNull();
  });

  it("active connection → Create ticket posts finding + connection, no credential", async () => {
    apiMock.listTicketingConnections.mockResolvedValue(
      connectionsResp([ACTIVE_CONN]),
    );
    apiMock.createTicket.mockResolvedValue({
      schema_version: "ticketing.ticket.v1",
      ticket: {
        id: "tk-1",
        tenant_id: "t1",
        connection_id: "conn-1",
        dedupe_key: findingKey(ITEM),
        provider: "jira",
        status: "open",
        external_id: "10001",
        key: "SEC-42",
        url: "https://itsm.example.com/browse/SEC-42",
        created_at: "",
        updated_at: "",
      },
      connection_id: "conn-1",
      provider: "jira",
      transport: "mcp",
      deduplicated: false,
      audit_metadata: {
        connect_once: true,
        per_action_credential: false,
        note: "",
      },
    });

    render(
      <TicketModal item={ITEM} existingTickets={[]} onClose={() => {}} />,
    );

    const createBtn = await screen.findByRole("button", {
      name: /Create ticket/i,
    });
    // Project prefilled from the connection default.
    expect(screen.getByPlaceholderText("e.g. SEC")).toHaveValue("SEC");

    fireEvent.click(createBtn);

    await waitFor(() => expect(apiMock.createTicket).toHaveBeenCalledOnce());
    const body = apiMock.createTicket.mock.calls[0]![0];
    expect(body.connection_id).toBe("conn-1");
    expect(body.finding_id).toBe(findingKey(ITEM));
    expect(body.project).toBe("SEC");
    expect(body.finding).toEqual(buildFinding(ITEM));
    // Connect-once invariant: no credential/token/url in the body.
    expect(body.api_token).toBeUndefined();
    expect(body.secret).toBeUndefined();
    expect(body.jira_url).toBeUndefined();

    // Newly filed ticket surfaces with its key + status.
    await waitFor(() =>
      expect(screen.getByText("SEC-42")).toBeInTheDocument(),
    );
    expect(screen.getByText("Open")).toBeInTheDocument();
  });

  it("renders an existing ticket status and Sync refreshes it", async () => {
    apiMock.listTicketingConnections.mockResolvedValue(
      connectionsResp([ACTIVE_CONN]),
    );
    const existing: TicketLink = {
      id: "tk-1",
      tenant_id: "t1",
      connection_id: "conn-1",
      dedupe_key: findingKey(ITEM),
      provider: "jira",
      status: "in_progress",
      external_id: "10001",
      key: "SEC-42",
      url: "",
      created_at: "",
      updated_at: "",
    };
    apiMock.syncTicket.mockResolvedValue({
      schema_version: "ticketing.ticket.v1",
      ticket: { ...existing, status: "done" },
      connection_id: "conn-1",
      provider: "jira",
      transport: "mcp",
      deduplicated: false,
      audit_metadata: { connect_once: true, per_action_credential: false, note: "" },
    });

    const onChanged = vi.fn();
    render(
      <TicketModal
        item={ITEM}
        existingTickets={[existing]}
        onClose={() => {}}
        onChanged={onChanged}
      />,
    );

    // Status chip shows the mapped label (in_progress → "In progress").
    expect(await screen.findByText("In progress")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Sync ticket status/i }));

    await waitFor(() => expect(apiMock.syncTicket).toHaveBeenCalledWith("tk-1"));
    await waitFor(() => expect(screen.getByText("Done")).toBeInTheDocument());
    expect(onChanged).toHaveBeenCalledOnce();
  });
});
