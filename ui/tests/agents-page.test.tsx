import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AgentsPage from "@/app/agents/page";

const { apiMock, deploymentMock, navigationMock } = vi.hoisted(() => ({
  apiMock: {
    listAgents: vi.fn(),
    getAgentDetail: vi.fn(),
  },
  deploymentMock: { counts: undefined as unknown },
  navigationMock: { query: "" },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(navigationMock.query),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/agents",
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    title,
    className,
    onClick,
  }: {
    href: string;
    children: React.ReactNode;
    title?: string;
    className?: string;
    onClick?: (e: React.MouseEvent) => void;
  }) => (
    <a href={href} title={title} className={className} onClick={onClick}>
      {children}
    </a>
  ),
}));

vi.mock("@/hooks/use-deployment-context", () => ({
  useDeploymentContext: () => ({ counts: deploymentMock.counts }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: apiMock };
});

const AGENTS = [
  {
    name: "Cursor",
    agent_type: "ide",
    agent_class: "client",
    source: "config",
    config_path: "/home/u/.cursor/mcp.json",
    status: "configured",
    mcp_servers: [
      {
        name: "github",
        transport: "stdio",
        command: "npx github-mcp",
        args: [],
        packages: [
          { name: "left-pad", version: "1.0.0", ecosystem: "npm" },
          { name: "requests", version: "2.0.0", ecosystem: "pypi" },
        ],
        tools: [{ name: "create_issue" }, { name: "list_repos" }],
        credential_env_vars: ["GITHUB_TOKEN"],
        env: { GITHUB_TOKEN: "x" },
        security_blocked: false,
      },
    ],
  },
  {
    name: "ClaudeDesktop",
    agent_type: "desktop",
    agent_class: "client",
    source: "config",
    config_path: "/home/u/.claude/config.json",
    status: "configured",
    mcp_servers: [
      {
        name: "filesystem",
        transport: "sse",
        url: "https://mcp.example.com/fs",
        packages: [],
        tools: [],
        credential_env_vars: [],
        env: {},
        security_blocked: true,
      },
    ],
  },
  {
    name: "SomeBinary",
    agent_type: "cli",
    status: "installed-not-configured",
    config_path: "/usr/local/bin/somebinary",
    mcp_servers: [],
  },
];

beforeEach(() => {
  deploymentMock.counts = undefined;
  navigationMock.query = "";
  apiMock.getAgentDetail.mockReset();
  apiMock.listAgents.mockReset();
  apiMock.listAgents.mockResolvedValue({ agents: AGENTS });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("AgentsPage list view", () => {
  it("renders KPIs and a dense configured-agents table", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-configured-table")).toBeInTheDocument());
    expect(screen.getByTestId("agents-kpis")).toBeInTheDocument();

    const table = within(screen.getByTestId("agents-configured-table"));
    expect(table.getByText("Cursor")).toBeInTheDocument();
    expect(table.getByText("ClaudeDesktop")).toBeInTheDocument();
    // installed-not-configured agent is not in the configured table
    expect(table.queryByText("SomeBinary")).not.toBeInTheDocument();
  });

  it("filters configured agents by search", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-configured-table")).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText("Search agents or agent type"), {
      target: { value: "cursor" },
    });

    const table = within(screen.getByTestId("agents-configured-table"));
    expect(table.getByText("Cursor")).toBeInTheDocument();
    expect(table.queryByText("ClaudeDesktop")).not.toBeInTheDocument();
  });

  it("opens an agent detail drawer with servers, tools, and credentials", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-configured-table")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("agents-configured-table")).getByText("Cursor"));

    const detail = within(screen.getByTestId("agent-detail-Cursor"));
    expect(detail.getByText("github")).toBeInTheDocument();
    expect(detail.getByText("create_issue")).toBeInTheDocument();
    expect(detail.getByText("GITHUB_TOKEN")).toBeInTheDocument();

    const dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByRole("link", { name: "Full detail" })).toHaveAttribute("href", "/agents?name=Cursor");
    expect(dialog.getByRole("link", { name: "Lifecycle graph" })).toHaveAttribute(
      "href",
      "/agents?name=Cursor&view=lifecycle"
    );
  });

  it("lists installed-but-not-configured agents in a collapsible table", async () => {
    render(<AgentsPage />);

    await waitFor(() => expect(screen.getByTestId("agents-configured-table")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Installed but not configured"));
    expect(within(screen.getByTestId("agents-installed-table")).getByText("SomeBinary")).toBeInTheDocument();
  });

  it.each(["", "invalid-capture-time"])("keeps unverified collection context explicit (%s)", async (captured_at) => {
    apiMock.listAgents.mockResolvedValue({ agents: [{ ...AGENTS[0], discovery_envelope: {
      envelope_version: 1, scan_mode: "unknown", redaction_status: "unknown", captured_at,
      discovery_scope: [], permissions_used: ["iam:GetRole"],
    } }] });
    render(<AgentsPage />);
    await waitFor(() => expect(screen.getByTestId("agents-configured-table")).toBeInTheDocument());
    fireEvent.click(within(screen.getByTestId("agents-configured-table")).getByText("Cursor"));
    const detail = within(screen.getByTestId("agent-detail-Cursor"));
    expect(detail.getByText("Collection context")).toBeInTheDocument();
    expect(detail.getByText("redaction: unknown")).toBeInTheDocument();
    expect(detail.getByText(/Capture time unknown/)).toBeInTheDocument();
    expect(detail.getByText("Reported permissions (1)")).toBeInTheDocument();
    expect(detail.queryByText(/Scan ran from/)).not.toBeInTheDocument();
    expect(detail.queryByText(/Invalid Date/)).not.toBeInTheDocument();
  });
});

describe("AgentsPage agent population", () => {
  const subtitle = () => screen.getByText(/Discovered AI clients\/hosts/);

  it("shows the canonical estate agent count and labels the host-discovered list as such", async () => {
    deploymentMock.counts = { agents: { total: 43, scan_id: "scan-9", basis: "graph_agents" } };
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(subtitle()).toHaveTextContent("with their MCP servers on this API host. Estate agents: 43 Open agent inventory");
    expect(within(subtitle()).getByRole("link", { name: "Open agent inventory" })).toHaveAttribute("href", "/inventory?type=agent");
    expect(kpis.getByText("On this host")).toBeInTheDocument();
    expect(kpis.queryByText("Agents")).not.toBeInTheDocument();
  });

  it("keeps the estate count visible when nothing is configured on the API host", async () => {
    deploymentMock.counts = { agents: { total: 0, scan_id: null, basis: "graph_agents" } };
    apiMock.listAgents.mockResolvedValue({ agents: [] });
    render(<AgentsPage />);

    await waitFor(() => expect(subtitle()).toHaveTextContent("Estate agents: 0"));
    expect(within(subtitle()).getByRole("link", { name: "Open agent inventory" })).toBeInTheDocument();
  });

  it("labels a scanned-estate response as scanned agents, never as this API host", async () => {
    apiMock.listAgents.mockResolvedValue({
      scope: "scanned_estate",
      count: 1,
      agents: [
        {
          name: "project:sampleapp",
          agent_type: "custom",
          source: "project",
          status: "configured",
          config_path: "/work/sampleapp",
          mcp_servers: [
            { name: "github", surface: "mcp-server", packages: [], env: { GITHUB_PERSONAL_ACCESS_TOKEN: "***" } },
            { name: "filesystem", surface: "mcp-server", packages: [] },
            { name: "app", surface: "other", command: "project", packages: [{ name: "pyyaml", version: "5.3", ecosystem: "pypi" }] },
            { name: "ai-inventory", surface: "ai-inventory", packages: [] },
          ],
        },
      ],
    });
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("Scanned agents")).toBeInTheDocument();
    expect(kpis.queryByText("On this host")).not.toBeInTheDocument();
    expect(subtitle()).not.toHaveTextContent("on this API host");
    // Manifest directories and the AI-inventory wrapper are not MCP servers.
    const mcpServersCell = kpis.getByText("MCP servers").parentElement!.parentElement!;
    expect(within(mcpServersCell).getByText("2")).toBeInTheDocument();
  });

  it("omits the estate count when the server does not report one", async () => {
    render(<AgentsPage />);

    const kpis = within(await screen.findByTestId("agents-kpis"));
    expect(kpis.getByText("On this host")).toBeInTheDocument();
    expect(subtitle()).not.toHaveTextContent("Estate agents");
    expect(screen.queryByRole("link", { name: "Open agent inventory" })).not.toBeInTheDocument();
  });
});


it("does not call an agent clean when no identity-linked findings are available", async () => {
  navigationMock.query = "name=agent-id-1";
  apiMock.getAgentDetail.mockResolvedValue({
    agent: { ...AGENTS[0], mcp_servers: [] },
    summary: { total_servers: 0, total_packages: 0, total_tools: 0, total_credentials: 0, total_vulnerabilities: 0, severity_breakdown: {} },
    blast_radius: [], credentials: [], fleet: null,
  });
  render(<AgentsPage />);
  expect(await screen.findByText("No attributed findings")).toHaveAttribute("title", expect.stringContaining("coverage may be incomplete"));
  expect(screen.queryByText("Clean")).not.toBeInTheDocument();
  expect(apiMock.getAgentDetail).toHaveBeenCalledWith("agent-id-1");
});
