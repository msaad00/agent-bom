import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphLegend } from "@/components/graph-chrome";

describe("GraphLegend", () => {
  it("groups entity legend rows by semantic layer and keeps relationships separate", () => {
    render(
      <GraphLegend
        embedded
        items={[
          { label: "Agent", color: "#10b981", layer: "orchestration", kind: "node", shape: "dot" },
          { label: "MCP Server", color: "#3b82f6", layer: "mcp_server", kind: "node", shape: "square" },
          { label: "Package", color: "#52525b", layer: "package", kind: "node", shape: "pill" },
          { label: "Vulnerability", color: "#ef4444", layer: "finding", kind: "node", shape: "diamond" },
          { label: "Uses", color: "#10b981", kind: "edge", lineStyle: "solid" },
        ]}
      />,
    );

    expect(screen.getByText("Orchestration")).toBeInTheDocument();
    expect(screen.getByText("MCP Servers")).toBeInTheDocument();
    expect(screen.getByText("Packages")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
    expect(screen.getByText("Relationships")).toBeInTheDocument();
    expect(screen.getByText("Uses")).toBeInTheDocument();
  });
});
