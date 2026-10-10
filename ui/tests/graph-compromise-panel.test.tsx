import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphCompromisePanel } from "@/components/graph-compromise-panel";
import { api } from "@/lib/api";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ loading: false, session: { tenant_id: "tenant-a" } }) }));
afterEach(() => vi.restoreAllMocks());

function result() {
  return { scan_id: "scan-one", snapshot_generation: "revision-one", actions: [], relationships_examined: 0, truncated: false };
}

it("requires an explicit assumption and never interprets an empty assessment as safe", async () => {
  const call = vi.spyOn(api, "assessCompromise").mockResolvedValue(result() as never);
  render(<GraphCompromisePanel nodeId="node:one" scanId="scan-one" snapshotGeneration="revision-one" />);
  expect(call).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Assess assumed compromise"));
  expect(screen.getByRole("button", { name: "Assess evidence" })).toBeDisabled();
  fireEvent.click(screen.getByLabelText("Assume control of this node"));
  fireEvent.click(screen.getByRole("button", { name: "Assess evidence" }));
  await screen.findByText(/No direct action receipts were returned/);
  expect(screen.getByText(/Collection coverage remains unknown/)).toBeVisible();
  expect(call.mock.calls[0]![0]).toMatchObject({ root_node_id: "node:one", scan_id: "scan-one", snapshot_generation: "revision-one", assume_control: true });
});

it("discards an in-flight result when the selected node changes", async () => {
  let complete!: (value: never) => void;
  vi.spyOn(api, "assessCompromise").mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
  const { rerender } = render(<GraphCompromisePanel nodeId="node:one" scanId="scan-one" />);
  fireEvent.click(screen.getByText("Assess assumed compromise"));
  fireEvent.click(screen.getByLabelText("Assume control of this node"));
  fireEvent.click(screen.getByRole("button", { name: "Assess evidence" }));
  rerender(<GraphCompromisePanel nodeId="node:two" scanId="scan-one" />);
  complete(result() as never);
  await waitFor(() => expect(screen.queryByText(/No direct action receipts/)).not.toBeInTheDocument());
  expect(screen.getByLabelText("Assume control of this node")).not.toBeChecked();
});

it("requires both the affected component and exploitation assumption for a finding", () => {
  render(<GraphCompromisePanel nodeId="finding:one" scanId="scan-one" findingRoot />);
  fireEvent.click(screen.getByText("Assess assumed compromise"));
  fireEvent.click(screen.getByLabelText("Assume control of this node"));
  expect(screen.getByRole("button", { name: "Assess evidence" })).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Affected component node ID"), { target: { value: "pkg:one" } });
  expect(screen.getByRole("button", { name: "Assess evidence" })).toBeDisabled();
  fireEvent.click(screen.getByLabelText("Assume exploitation of this finding"));
  expect(screen.getByRole("button", { name: "Assess evidence" })).toBeEnabled();
});

it("shows a failed read as unavailable without a clean or empty verdict", async () => {
  vi.spyOn(api, "assessCompromise").mockRejectedValue(new Error("secret internal database error"));
  render(<GraphCompromisePanel nodeId="node:one" scanId="scan-one" />);
  fireEvent.click(screen.getByText("Assess assumed compromise"));
  fireEvent.click(screen.getByLabelText("Assume control of this node"));
  fireEvent.click(screen.getByRole("button", { name: "Assess evidence" }));
  await screen.findByRole("alert");
  expect(screen.queryByText(/secret internal/)).not.toBeInTheDocument();
  expect(screen.queryByText(/No direct action receipts/)).not.toBeInTheDocument();
});

it("locks assumptions while a request is pending", async () => {
  let complete!: (value: never) => void;
  vi.spyOn(api, "assessCompromise").mockImplementation(() => new Promise((resolve) => { complete = resolve; }));
  render(<GraphCompromisePanel nodeId="finding:one" scanId="scan-one" findingRoot />);
  fireEvent.click(screen.getByText("Assess assumed compromise"));
  fireEvent.click(screen.getByLabelText("Assume control of this node"));
  fireEvent.change(screen.getByLabelText("Affected component node ID"), { target: { value: "principal:one" } });
  fireEvent.click(screen.getByLabelText("Assume exploitation of this finding"));
  fireEvent.click(screen.getByRole("button", { name: "Assess evidence" }));
  expect(screen.getByLabelText("Assume control of this node")).toBeDisabled();
  expect(screen.getByLabelText("Affected component node ID")).toBeDisabled();
  expect(screen.getByLabelText("Assume exploitation of this finding")).toBeDisabled();
  complete(result() as never);
  await screen.findByText(/No direct action receipts/);
  expect(screen.getByLabelText("Assume control of this node")).toBeEnabled();
});
