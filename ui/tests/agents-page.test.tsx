import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AgentsPage from "@/app/agents/page";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    listAgents: vi.fn(),
  },
}));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
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
  useDeploymentContext: () => ({ counts: undefined }),
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
});
