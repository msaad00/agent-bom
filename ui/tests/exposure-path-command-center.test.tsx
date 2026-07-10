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
  it("renders a compact path header with collapsed evidence by default", () => {
    render(
      <ExposurePathCommandCenter
        path={basePath}
        actions={[{ title: "Validate the lead finding", detail: "Open CVE evidence.", href: "/findings?cve=CVE-2026-0002" }]}
      />,
    );

    expect(
      screen.getByText("Analyst Agent → Database service → werkzeug → CVE-2026-0002 → Execute Sql → DATABASE URL"),
    ).toBeInTheDocument();
    expect(screen.queryByText("What is exposed")).not.toBeInTheDocument();
    expect(screen.getByText("Evidence & relationships")).toBeInTheDocument();
    expect(screen.queryByText("Evidence drawer")).not.toBeVisible();
    expect(screen.getByText("Validate the lead finding")).toBeInTheDocument();
  });
});
