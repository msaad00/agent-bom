import { render, screen, fireEvent, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ExposurePathCommandCenter } from "@/components/exposure-path-command-center";
import type { ExposurePath } from "@/lib/exposure-path";

const basePath: ExposurePath = {
  id: "path-1",
  label: "analyst-agent -> database -> werkzeug -> CVE-2026-0002",
  summary: "Agent reaches a vulnerable package through the database MCP server.",
  riskScore: 9.6,
  severity: "critical",
  source: { id: "agent:analyst", label: "analyst-agent", role: "agent" },
  target: { id: "vuln:werkzeug:CVE-2026-0002", label: "CVE-2026-0002", role: "finding", severity: "critical" },
  hops: [
    { id: "agent:analyst", label: "analyst-agent", role: "agent" },
    { id: "server:database", label: "database", role: "server" },
    { id: "pkg:werkzeug", label: "werkzeug@2.2.2", role: "package", severity: "critical" },
    { id: "vuln:werkzeug:CVE-2026-0002", label: "CVE-2026-0002", role: "finding", severity: "critical" },
    { id: "tool:execute_sql", label: "execute_sql", role: "tool" },
    { id: "cred:DATABASE_URL", label: "DATABASE_URL", role: "credential" },
  ],
  relationships: [
    {
      id: "agent->server",
      source: "agent:analyst",
      target: "server:database",
      relationship: "uses",
      direction: "directed",
      traversable: true,
      confidence: "observed",
    },
    {
      id: "pkg->vuln",
      source: "pkg:werkzeug",
      target: "vuln:werkzeug:CVE-2026-0002",
      relationship: "vulnerable_to",
      direction: "directed",
      traversable: true,
      confidence: "scanner",
    },
  ],
  nodeIds: ["agent:analyst", "server:database", "pkg:werkzeug", "vuln:werkzeug:CVE-2026-0002"],
  edgeIds: ["agent->server", "pkg->vuln"],
  findings: ["CVE-2026-0002"],
  affectedAgents: ["analyst-agent"],
  affectedServers: ["database"],
  reachableTools: ["execute_sql"],
  exposedCredentials: ["DATABASE_URL"],
  dependencyContext: {
    packageName: "werkzeug",
    packageVersion: "2.2.2",
    ecosystem: "pypi",
    serverName: "database",
  },
  fix: {
    label: "Upgrade werkzeug",
    version: "2.2.3",
  },
  evidence: {
    cvssScore: 9.8,
    epssScore: 0.834,
    isKev: true,
    attackVectorSummary: "Database MCP server exposes SQL execution.",
  },
};

/**
 * Longest board the product has to frame: agent -> server -> package -> finding
 * -> 3 tools -> 3 credentials -> data store. At 11 hops the natural board is
 * 3004px, more than twice the widest desktop content width the shell allows.
 */
const longPath: ExposurePath = {
  ...basePath,
  id: "path-long",
  hops: [
    { id: "agent:cursor", label: "Cursor IDE Agent", role: "agent" },
    { id: "server:shell-runner", label: "shell-runner-server", role: "server" },
    { id: "pkg:pyyaml", label: "pyyaml@5.3", role: "package" },
    { id: "vuln:CVE-2020-14343", label: "CVE-2020-14343", role: "finding" },
    { id: "tool:run_shell", label: "run_shell", role: "tool" },
    { id: "tool:exec_command", label: "exec_command", role: "tool" },
    { id: "tool:read_file", label: "read_file", role: "tool" },
    { id: "cred:SNOWFLAKE_PASSWORD", label: "SNOWFLAKE_PASSWORD", role: "credential" },
    { id: "cred:DATABASE_URL", label: "DATABASE_URL", role: "credential" },
    { id: "cred:AWS_SECRET_ACCESS_KEY", label: "AWS_SECRET_ACCESS_KEY", role: "credential" },
    { id: "store:warehouse", label: "prod-warehouse", role: "environment" },
  ],
};

describe("ExposurePathCommandCenter", () => {
  it("renders a compact path header with collapsed evidence by default", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        actions={[{ title: "Validate the lead finding", detail: "Open CVE evidence.", href: "/findings?cve=CVE-2026-0002" }]}
      />,
    );

    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(
      "Analyst Agent → Database service → werkzeug → CVE-2026-0002 → Execute Sql → DATABASE URL",
    );
    expect(screen.getByTestId("exposure-path-hop-title")).toBeInTheDocument();
    expect(screen.getByText("Analyst Agent")).toBeInTheDocument();
    expect(within(screen.getByTestId("exposure-path-hop-title")).getByText("CVE-2026-0002")).toBeInTheDocument();
    expect(screen.queryByText("What is exposed")).not.toBeInTheDocument();
    expect(screen.getByText("Evidence & relationships")).toBeInTheDocument();
    expect(screen.queryByText("Evidence drawer")).not.toBeVisible();
    expect(screen.getByText("Validate the lead finding")).toBeInTheDocument();
  });

  it("gives the title a full mobile row and keeps the summary readable", () => {
    render(<ExposurePathCommandCenter path={basePath} />);

    const title = screen.getByRole("heading", { level: 2 });
    expect(title.parentElement).toHaveClass("w-full");
    expect(screen.getByText(basePath.summary!)).toHaveClass("line-clamp-3");
  });

  it("presents a single-node risk signal as one node instead of zero hops", () => {
    const resource = { id: "resource-1", label: "Prod Bastion", role: "server" as const };
    render(
      <ExposurePathCommandCenter
        path={{
          ...basePath,
          source: resource,
          target: resource,
          hops: [resource],
          affectedAgents: [],
        }}
      />,
    );

    expect(screen.getByText("Path span")).toBeInTheDocument();
    expect(screen.getByText("1 node")).toBeInTheDocument();
    expect(screen.queryByText("Hops")).not.toBeInTheDocument();
  });

  it("shows one representation at a time and defaults to the path view", () => {
    render(<ExposurePathCommandCenter path={basePath} />);

    // Path view: the selected-path DAG is rendered; the neighbor list and the
    // interactive-graph hint are not stacked underneath it.
    expect(
      screen.getByRole("img", { name: /Selected exposure path graph for/ }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Expand path neighbors")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/Interactive graph opens below/),
    ).not.toBeInTheDocument();
  });

  it("switches to the neighbor list and the interactive-graph hint via the toggle", () => {
    const onViewChange = vi.fn();
    render(
      <ExposurePathCommandCenter
        path={basePath}
        view="list"
        onViewChange={onViewChange}
      />,
    );

    // Controlled "list" view swaps the DAG for the neighbor explorer.
    expect(screen.getByText("Expand path neighbors")).toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: /Selected exposure path graph for/ }),
    ).not.toBeInTheDocument();

    // The toggle reports view changes so the page can render the interactive
    // graph on demand.
    fireEvent.click(screen.getByRole("button", { name: /Graph/ }));
    expect(onViewChange).toHaveBeenCalledWith("graph");
  });

  it("renders a hint instead of a reserved blank canvas when no graph slot is supplied", () => {
    render(<ExposurePathCommandCenter path={basePath} view="graph" onViewChange={vi.fn()} />);

    expect(screen.getByText(/Interactive graph loads here/)).toBeInTheDocument();
    expect(
      screen.queryByRole("img", { name: /Selected exposure path graph for/ }),
    ).not.toBeInTheDocument();
  });

  it("fits a long chain in the first frame and names the hops it summarises", () => {
    render(<ExposurePathCommandCenter path={longPath} />);

    const board = screen.getByRole("img", { name: /Selected exposure path graph for/ });
    // Shrink-to-fit board: capped at its natural width, never a fixed overflow.
    expect(board).toHaveAttribute("width", "100%");
    expect(board.style.maxWidth).toBe("884px");
    // Collapsed board fits, so its wrapper must not offer horizontal scroll.
    expect(screen.getByTestId("exposure-path-graph-scroll")).not.toHaveClass("overflow-x-auto");

    // Entry hop and crown-jewel hop stay pinned; the middle is summarised by
    // kind so the tool and credential hops are still named in the first frame.
    expect(within(board).getByText("Cursor IDE Agent")).toBeInTheDocument();
    expect(within(board).getByText("prod-warehouse")).toBeInTheDocument();
    expect(within(board).getByText("+9 hops hidden")).toBeInTheDocument();
    expect(within(board).getByText("3 credentials · 3 tools")).toBeInTheDocument();
    expect(within(board).queryByText("run_shell")).not.toBeInTheDocument();
  });

  it("round-trips the long-chain board between collapsed and fully expanded", () => {
    render(<ExposurePathCommandCenter path={longPath} />);

    const toggle = screen.getByRole("button", { name: "Show all 11 hops" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(toggle);
    const expandedBoard = screen.getByRole("img", { name: /Selected exposure path graph for/ });
    expect(within(expandedBoard).getByText("run_shell")).toBeInTheDocument();
    expect(within(expandedBoard).getByText("exec_command")).toBeInTheDocument();
    expect(within(expandedBoard).getByText("DATABASE_URL")).toBeInTheDocument();
    expect(within(expandedBoard).queryByText("+9 hops hidden")).not.toBeInTheDocument();
    // Expanded board renders at 1x and scrolls horizontally instead of scaling.
    expect(expandedBoard).toHaveAttribute("width", "3004");
    expect(screen.getByTestId("exposure-path-graph-scroll")).toHaveClass("overflow-x-auto");

    const collapse = screen.getByRole("button", { name: "Collapse to fit" });
    expect(collapse).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(collapse);
    const collapsedBoard = screen.getByRole("img", { name: /Selected exposure path graph for/ });
    expect(within(collapsedBoard).getByText("+9 hops hidden")).toBeInTheDocument();
    expect(within(collapsedBoard).queryByText("run_shell")).not.toBeInTheDocument();
  });

  it("re-enters the fit-first frame when a different path is selected", () => {
    const { rerender } = render(<ExposurePathCommandCenter path={longPath} />);
    fireEvent.click(screen.getByRole("button", { name: "Show all 11 hops" }));
    expect(screen.getByRole("button", { name: "Collapse to fit" })).toBeInTheDocument();

    // Selecting another long path must not inherit the expanded board — the
    // first frame of a new investigation has to fit again.
    rerender(<ExposurePathCommandCenter path={{ ...longPath, id: "path-long-2" }} />);
    expect(screen.getByRole("button", { name: "Show all 11 hops" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Collapse to fit" })).not.toBeInTheDocument();
  });

  it("does not offer a collapse toggle for a path that already fits", () => {
    render(<ExposurePathCommandCenter path={{ ...basePath, hops: basePath.hops.slice(0, 4) }} />);

    expect(screen.queryByRole("button", { name: /Show all \d+ hops/ })).not.toBeInTheDocument();
    expect(screen.getByTestId("exposure-path-graph-scroll")).not.toHaveClass("overflow-x-auto");
  });

  it("renders the interactive graph inline in graph view instead of an 'opens below' placeholder", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        view="graph"
        onViewChange={vi.fn()}
        graphSlot={<div data-testid="inline-investigation-graph">live graph</div>}
      />,
    );

    // The graph is shown right here, in the Graph slot — not a placeholder
    // pointing at a separate panel further down the page.
    expect(screen.getByTestId("inline-investigation-graph")).toBeInTheDocument();
    expect(screen.queryByText(/Interactive graph loads here/)).not.toBeInTheDocument();
    expect(screen.queryByText(/opens below/)).not.toBeInTheDocument();
    // Only the graph slot renders — the path DAG is not stacked underneath.
    expect(
      screen.queryByRole("img", { name: /Selected exposure path graph for/ }),
    ).not.toBeInTheDocument();
  });
});
