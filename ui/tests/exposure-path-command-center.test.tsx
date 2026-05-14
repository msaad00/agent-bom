import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

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

describe("ExposurePathCommandCenter", () => {
  it("renders the selected exposure path as a command-center investigation", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        actions={[{ title: "Validate the lead finding", detail: "Open CVE evidence.", href: "/findings?cve=CVE-2026-0002" }]}
      />,
    );

    expect(screen.getByText("Command center")).toBeInTheDocument();
    expect(screen.getByText("analyst-agent -> werkzeug@2.2.2 -> CVE-2026-0002")).toBeInTheDocument();
    expect(screen.getByText("What is exposed")).toBeInTheDocument();
    expect(screen.getByText("Why it matters")).toBeInTheDocument();
    expect(screen.getByText("What proves it")).toBeInTheDocument();
    expect(screen.getByText("What fixes it")).toBeInTheDocument();
    expect(screen.getByText("Selected path graph")).toBeInTheDocument();
    expect(screen.getByText("Relationship proof")).toBeInTheDocument();
    expect(screen.getByText("Evidence drawer")).toBeInTheDocument();
    expect(screen.getAllByText("uses").length).toBeGreaterThan(0);
    expect(screen.getAllByText("vulnerable_to").length).toBeGreaterThan(0);
    expect(screen.getAllByText("DATABASE_URL").length).toBeGreaterThan(0);
    expect(screen.getAllByText("execute_sql").length).toBeGreaterThan(0);
    expect(screen.getByText("CVSS 9.8")).toBeInTheDocument();
    expect(screen.getByText("EPSS 0.834")).toBeInTheDocument();
    expect(screen.getByText("KEV")).toBeInTheDocument();
    expect(screen.getByText("Validate the lead finding")).toBeInTheDocument();
  });
});
