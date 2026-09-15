import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { AISVSBenchmarkDetail } from "@/components/aisvs-benchmark-detail";
import type { AISVSComplianceResponse } from "@/lib/api-types";

it("shows recorded evidence and distinguishes evaluation errors from failures", () => {
  const data = { scan_id: "scan-evidence", benchmark: { checks: [
    { check_id: "V1.1", title: "Tool authorization", status: "fail", evidence: "Tool scope exceeds policy", recommendation: "Restrict tool scope" },
    { check_id: "V1.2", title: "Audit collection", status: "error", evidence: "Collector unavailable" },
    { check_id: "V1.3", title: "Model hosting", status: "not_applicable" },
  ] } } as AISVSComplianceResponse;
  render(<AISVSBenchmarkDetail data={data} />);
  expect(screen.getByText("Source scan: scan-evidence")).toBeInTheDocument();
  fireEvent.click(screen.getByText("Tool authorization"));
  expect(screen.getByText("Tool scope exceeds policy")).toBeVisible();
  expect(screen.getByText("Recommendation: Restrict tool scope")).toBeVisible();
  fireEvent.change(screen.getByRole("combobox", { name: "AISVS check status" }), { target: { value: "error" } });
  expect(screen.getByText("1 of 3 checks shown")).toBeInTheDocument();
  expect(screen.getByText("Audit collection")).toBeInTheDocument();
  expect(screen.queryByText("Tool authorization")).toBeNull();
});
