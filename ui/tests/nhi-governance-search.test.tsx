import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { NhiGovernancePanel } from "../components/nhi-governance-panel";

vi.mock("@/lib/api", () => ({ api: { getNhiGovernance: vi.fn(async () => ({
  scan_id: "snapshot-a", counts: { over_granted: 2, by_risk_band: { critical: 1 }, unavailable: null }, identities: Array.from({ length: 12 }, (_, i) => ({
    node_id: `role:account-${i}:reader`, name: "Data reader", risk_score: i,
  })),
})) } }));

it("disambiguates identical names and finds identities beyond the initial eight", async () => {
  render(<NhiGovernancePanel />);
  expect(await screen.findByText("role:account-0:reader")).toBeVisible();
  expect(screen.getAllByRole("link")).toHaveLength(8);
  expect(screen.getByText("risk band · critical")).toBeVisible();
  expect(screen.getByText("over granted")).toBeVisible();
  expect(screen.getByText(/Showing 8 of 12/)).toBeVisible();
  fireEvent.change(screen.getByRole("textbox", { name: /Find a discovered identity/ }), { target: { value: "account-11:" } });
  const link = screen.getByRole("link");
  expect(link).toHaveTextContent("role:account-11:reader");
  expect(link.getAttribute("href")).toContain("root=role%3Aaccount-11%3Areader");
  expect(link.getAttribute("href")).toContain("scan=snapshot-a");
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "absent" } });
  expect(screen.getByText(/Showing 0 of 0/)).toBeVisible();
  expect(screen.queryAllByRole("link")).toHaveLength(0);
});
