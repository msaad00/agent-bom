import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";

import { AiScanPanel } from "@/components/ai-scan-panel";
import { AI_SCAN_TYPES } from "@/lib/ai-scan";
import { api } from "@/lib/api";

describe("AiScanPanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("exposes all six AI/ML scan types as selectable tabs", () => {
    render(<AiScanPanel />);
    for (const type of AI_SCAN_TYPES) {
      expect(screen.getByRole("tab", { name: new RegExp(type.label, "i") })).toBeInTheDocument();
    }
    expect(AI_SCAN_TYPES).toHaveLength(6);
  });

  it("shows an honest empty state before any scan is run", () => {
    render(<AiScanPanel />);
    expect(screen.getByTestId("ai-scan-empty")).toBeInTheDocument();
    expect(screen.queryByTestId("ai-scan-results")).not.toBeInTheDocument();
  });

  it("runs a dataset-cards scan against the right endpoint and renders real results", async () => {
    const user = userEvent.setup();
    const spy = vi.spyOn(api, "scanDatasetCards").mockResolvedValue({
      scan_type: "dataset-cards",
      directories: ["/data"],
      results: [
        {
          datasets: [
            {
              name: "squad",
              license: null,
              source_file: "/data/squad/README.md",
              security_flags: [
                { severity: "MEDIUM", type: "UNLICENSED_DATASET", description: "No license." },
              ],
            },
          ],
          source_files: ["/data/squad/README.md"],
          warnings: ["heads up"],
          total_datasets: 1,
          flagged_count: 1,
        },
      ],
    });

    render(<AiScanPanel />);
    await user.type(screen.getByLabelText("Directories"), "/data");
    await user.click(screen.getByRole("button", { name: /^Add$/i }));
    await user.click(screen.getByRole("button", { name: /Run scan/i }));

    await waitFor(() => expect(screen.getByTestId("ai-scan-results")).toBeInTheDocument());
    expect(spy).toHaveBeenCalledWith({ directories: ["/data"] });
    expect(screen.getByText("squad")).toBeInTheDocument();
    // Warning from the API is surfaced verbatim.
    expect(screen.getByText("heads up")).toBeInTheDocument();
  });

  it("gates Run until a directory is provided", async () => {
    const user = userEvent.setup();
    render(<AiScanPanel />);
    expect(screen.getByRole("button", { name: /Run scan/i })).toBeDisabled();
    await user.type(screen.getByLabelText("Directories"), "/data");
    await user.click(screen.getByRole("button", { name: /^Add$/i }));
    expect(screen.getByRole("button", { name: /Run scan/i })).toBeEnabled();
  });

  it("runs a browser-extension scan with no path input required", async () => {
    const user = userEvent.setup();
    const spy = vi.spyOn(api, "scanBrowserExtensions").mockResolvedValue({
      scan_type: "browser-extensions",
      total: 1,
      critical: 1,
      high: 0,
      extensions: [
        {
          id: "abc",
          name: "Sketchy Helper",
          browser: "chrome",
          risk_level: "critical",
          permissions: ["debugger"],
          host_permissions: ["<all_urls>"],
          has_native_messaging: true,
          has_ai_host_access: true,
          risk_reasons: ["debugger permission"],
        },
      ],
    });

    render(<AiScanPanel />);
    await user.click(screen.getByRole("tab", { name: /Browser extensions/i }));
    // No inputs — Run is immediately available.
    await user.click(screen.getByRole("button", { name: /Run scan/i }));

    await waitFor(() => expect(spy).toHaveBeenCalledWith({ include_low_risk: false }));
    expect(screen.getByText("Sketchy Helper")).toBeInTheDocument();
    expect(screen.getByTestId("ai-scan-stats")).toBeInTheDocument();
  });

  it("scans model provenance only after a model id is entered", async () => {
    const user = userEvent.setup();
    const spy = vi.spyOn(api, "scanModelProvenance").mockResolvedValue({
      scan_type: "model-provenance",
      total: 1,
      unsafe_format: 1,
      results: [
        {
          model_id: "org/model",
          source: "huggingface",
          format: "pickle",
          is_safe_format: false,
          risk_level: "high",
          risk_flags: ["unsafe_format"],
        },
      ],
    });

    render(<AiScanPanel />);
    await user.click(screen.getByRole("tab", { name: /Model provenance/i }));
    expect(screen.getByRole("button", { name: /Run scan/i })).toBeDisabled();

    await user.type(screen.getByLabelText("HuggingFace models"), "org/model");
    // Two "Add" buttons (HF + Ollama); the first belongs to the HF input.
    await user.click(screen.getAllByRole("button", { name: /^Add$/i })[0]!);
    await user.click(screen.getByRole("button", { name: /Run scan/i }));

    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith({ hf_models: ["org/model"], ollama_models: [] }),
    );
    const results = screen.getByTestId("ai-scan-results");
    expect(within(results).getByText("org/model")).toBeInTheDocument();
    expect(within(results).getByText("unsafe")).toBeInTheDocument();
  });

  it("opens a detail drawer with the security flags for a row", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "scanModelFiles").mockResolvedValue({
      scan_type: "model-files",
      total: 1,
      manifest_total: 0,
      unsafe: 1,
      files: [
        {
          path: "/models/evil.pkl",
          filename: "evil.pkl",
          format: "Pickle",
          ecosystem: "scikit-learn/Python",
          size_human: "2.0 KB",
          security_flags: [
            { severity: "CRITICAL", type: "PICKLE_REDUCE", description: "Arbitrary code execution." },
          ],
        },
      ],
      manifests: [],
      warnings: [],
    });

    render(<AiScanPanel />);
    await user.click(screen.getByRole("tab", { name: /Model files/i }));
    await user.type(screen.getByLabelText("Directories"), "/models");
    await user.click(screen.getByRole("button", { name: /^Add$/i }));
    await user.click(screen.getByRole("button", { name: /Run scan/i }));

    await waitFor(() => expect(screen.getByText("evil.pkl")).toBeInTheDocument());
    await user.click(screen.getByText("evil.pkl"));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Arbitrary code execution.")).toBeInTheDocument();
    expect(within(dialog).getByText("PICKLE_REDUCE")).toBeInTheDocument();
  });

  it("renders an error state when the scan endpoint fails", async () => {
    const user = userEvent.setup();
    vi.spyOn(api, "scanBrowserExtensions").mockRejectedValue(new Error("boom"));

    render(<AiScanPanel />);
    await user.click(screen.getByRole("tab", { name: /Browser extensions/i }));
    await user.click(screen.getByRole("button", { name: /Run scan/i }));

    await waitFor(() => expect(screen.getByTestId("ai-scan-error")).toBeInTheDocument());
    expect(screen.getAllByText("boom").length).toBeGreaterThan(0);
  });
});
