import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GraphEvidenceExportButton, GraphLegend } from "@/components/graph-chrome";
import { api } from "@/lib/api";

afterEach(() => {
  vi.restoreAllMocks();
});

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

  it("opens the legend by default for capture-ready graph views", () => {
    render(
      <GraphLegend
        defaultOpen
        items={[
          { label: "Agent", color: "#10b981", layer: "orchestration", kind: "node", shape: "dot" },
          { label: "Uses", color: "#10b981", kind: "edge", lineStyle: "solid" },
        ]}
      />,
    );

    expect(screen.getByRole("button", { name: /hide legend/i })).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText("Orchestration")).toBeInTheDocument();
    expect(screen.getByText("Relationships")).toBeInTheDocument();
  });
});

describe("GraphEvidenceExportButton", () => {
  it("downloads the selected scan graph in the chosen evidence format", async () => {
    const downloadSpy = vi
      .spyOn(api, "downloadScanGraph")
      .mockResolvedValue(new Blob(["graph"], { type: "application/json" }));
    const createObjectUrlSpy = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:graph");
    const revokeObjectUrlSpy = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const anchorClickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    render(<GraphEvidenceExportButton scanId="scan-123" filenamePrefix="selected-graph" />);

    fireEvent.change(screen.getByLabelText("Graph evidence format"), { target: { value: "mermaid" } });
    fireEvent.click(screen.getByRole("button", { name: /download graph evidence/i }));

    await waitFor(() => expect(downloadSpy).toHaveBeenCalledWith("scan-123", "mermaid"));
    expect(createObjectUrlSpy).toHaveBeenCalled();
    expect(anchorClickSpy).toHaveBeenCalled();
    expect(revokeObjectUrlSpy).toHaveBeenCalledWith("blob:graph");
  });

  it("stays disabled until a scan is selected", () => {
    render(<GraphEvidenceExportButton />);

    expect(screen.getByRole("button", { name: /download graph evidence/i })).toBeDisabled();
  });
});
