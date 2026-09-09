import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { RuntimeProfilesPanel } from "@/app/gateway/RuntimeProfilesPanel";
import { ApiError } from "@/lib/api-errors";

const mocks = vi.hoisted(() => ({ list: vi.fn(), identities: vi.fn(), create: vi.fn(), update: vi.fn(), revoke: vi.fn(), preview: vi.fn(), write: true }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: { tenant_id: "tenant-a", subject: "operator" }, hasCapability: (capability: string) => capability === "policy.manage" && mocks.write }) }));
vi.mock("@/lib/api", () => ({ api: { listRuntimeProfiles: mocks.list, listIdentities: mocks.identities, createRuntimeProfile: mocks.create, updateRuntimeProfile: mocks.update, revokeRuntimeProfile: mocks.revoke, evaluateRuntimeProfile: mocks.preview } }));
const profile = { config_id: "profile-a", tenant_id: "tenant-a", name: "Finance production", identity_id: "identity-a", profile_id: "finance", revision: 3, status: "active", revoked: false, issuer: "agent-bom", environment: "prod", connector_ids: ["filesystem"], allowed_tools: ["read_file"], required_scopes: ["tools:read"], policy_ids: ["policy-finance"], connection_ids: [], expires_at: "" };
beforeEach(() => {
  [mocks.list, mocks.identities, mocks.create, mocks.update, mocks.revoke, mocks.preview].forEach(mock => mock.mockReset());
  mocks.write = true;
  mocks.list.mockResolvedValue({ assignments: [profile] });
  mocks.identities.mockResolvedValue({ identities: [{ identity_id: "identity-new", agent_id: "payroll-agent", blueprint_id: "finance", status: "active" }] });
  mocks.create.mockResolvedValue({ assignment: profile }); mocks.update.mockResolvedValue({ assignment: profile }); mocks.revoke.mockResolvedValue({ assignment: profile });
  mocks.preview.mockResolvedValue({ profile_allowed: true, reason_code: "resolved", scope: "profile_contract_only", executed: false });
});
it("creates only a managed identity-bound profile with its blueprint", async () => {
  render(<RuntimeProfilesPanel />);
  await screen.findByText(/Finance production/);
  fireEvent.click(screen.getByRole("button", { name: "Create profile" }));
  await screen.findByText("New managed profile");
  fireEvent.change(screen.getByLabelText("Profile name"), { target: { value: "New production" } });
  fireEvent.change(screen.getByLabelText("Managed identity"), { target: { value: "identity-new" } });
  fireEvent.change(screen.getByLabelText("Upstream connector IDs (comma separated)"), { target: { value: "filesystem, filesystem" } });
  fireEvent.click(screen.getByRole("button", { name: "Create managed profile" }));
  await waitFor(() => expect(mocks.create).toHaveBeenCalledWith(expect.objectContaining({ identity_id: "identity-new", profile_id: "finance", environment: "prod", connector_ids: ["filesystem"] })));
});
it("sends expected_revision and reports conflicts without pretending to save", async () => {
  mocks.update.mockRejectedValue(new ApiError("secret database", { status: 409, statusText: "Conflict", url: "/profile", method: "PUT" }));
  render(<RuntimeProfilesPanel />);
  fireEvent.click(await screen.findByRole("button", { name: "Inspect profile" }));
  fireEvent.change(screen.getByLabelText("Environment"), { target: { value: "staging" } });
  fireEvent.click(screen.getByRole("button", { name: "Save profile revision" }));
  await waitFor(() => expect(mocks.update).toHaveBeenCalledWith("profile-a", expect.objectContaining({ expected_revision: 3, environment: "staging" })));
  expect(await screen.findByRole("alert")).toHaveTextContent("Reload profiles");
  expect(screen.queryByText(/secret database/)).not.toBeInTheDocument();
});
it("labels validation as simulation and tests the saved profile rather than unsaved edits", async () => {
  render(<RuntimeProfilesPanel />);
  fireEvent.click(await screen.findByRole("button", { name: "Validate profile" }));
  expect(await screen.findByText(/Simulation only/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Inspect profile" }));
  fireEvent.change(screen.getByLabelText("Environment"), { target: { value: "unsaved" } });
  fireEvent.click(screen.getByRole("button", { name: "Test saved profile" }));
  await waitFor(() => expect(mocks.preview).toHaveBeenLastCalledWith(expect.objectContaining({ environment: "prod", upstream: "filesystem", tool: "read_file" })));
});
it("requires explicit revocation confirmation and hides writes from viewers", async () => {
  const view = render(<RuntimeProfilesPanel />);
  fireEvent.click(await screen.findByRole("button", { name: "Revoke profile" }));
  expect(mocks.revoke).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
  await waitFor(() => expect(mocks.revoke).toHaveBeenCalledWith("profile-a"));
  view.unmount(); mocks.write = false;
  render(<RuntimeProfilesPanel />);
  expect(await screen.findByText(/Read-only access/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Create profile" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revoke profile" })).not.toBeInTheDocument();
});
