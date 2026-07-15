import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import BlueprintsPage from "@/app/blueprints/page";

const { apiMock, authMock } = vi.hoisted(() => ({
  apiMock: {
    listBlueprints: vi.fn(),
    getBlueprint: vi.fn(),
    seedBlueprints: vi.fn(),
    submitBlueprintVersion: vi.fn(),
    approveBlueprintVersion: vi.fn(),
    rejectBlueprintVersion: vi.fn(),
  },
  authMock: {
    // Contributor (analyst): has scan.run but NOT policy.manage, so it may
    // author/seed but must not be able to approve.
    capabilities: ["inventory.read", "scan.run"],
    authRequired: true,
  },
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/components/auth-provider", () => ({
  useAuthState: () => ({
    session: { authenticated: true, auth_required: authMock.authRequired, role: "analyst", tenant_id: "t1" },
    loading: false,
    error: null,
    refresh: vi.fn(),
    hasCapability: (capability: string) => authMock.capabilities.includes(capability),
  }),
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));

function bp(overrides: Record<string, unknown> = {}) {
  return {
    blueprint_id: "bp_seed_developer",
    tenant_id: "t1",
    name: "Developer",
    owner: "appsec",
    owner_type: "role_archetype",
    description: "Build and debug code",
    created_at: "2026-07-14T00:00:00Z",
    updated_at: "2026-07-14T00:00:00Z",
    current_version: 0,
    latest_version: 1,
    approval_status: "pending",
    seeded_from: "developer",
    ...overrides,
  };
}

function emptyComposition() {
  return { agents: [], models: [], tools: [], datasets: [], identities: [], owners: [], guardrails: [] };
}

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  authMock.capabilities = ["inventory.read", "scan.run"];
  authMock.authRequired = true;
  apiMock.listBlueprints.mockResolvedValue({ schema_version: "governance.blueprints.v1", tenant_id: "t1", count: 1, next_offset: null, blueprints: [bp()] });
  apiMock.getBlueprint.mockResolvedValue({
    schema_version: "governance.blueprints.v1",
    tenant_id: "t1",
    blueprint: bp(),
    versions: [
      {
        version_id: "bpv_1",
        blueprint_id: "bp_seed_developer",
        tenant_id: "t1",
        version: 1,
        status: "pending",
        composition: { ...emptyComposition(), tools: ["repo_read"] },
        created_at: "2026-07-14T00:00:00Z",
        created_by: "dev",
        submitted_at: "2026-07-14T01:00:00Z",
        submitted_by: "dev",
        decided_at: "",
        approver: "",
        decision_note: "",
        seeded_from: "developer",
      },
    ],
  });
  apiMock.seedBlueprints.mockResolvedValue({ seeded_count: 5, blueprints: [] });
});

afterEach(() => vi.restoreAllMocks());

describe("BlueprintsPage", () => {
  it("renders persisted blueprints from the control plane", async () => {
    render(<BlueprintsPage />);
    await waitFor(() => expect(screen.getByText("Developer")).toBeInTheDocument());
    expect(apiMock.listBlueprints).toHaveBeenCalled();
    expect(screen.getByText("seeded from developer")).toBeInTheDocument();
  });

  it("offers an in-product seed action when empty", async () => {
    apiMock.listBlueprints.mockResolvedValueOnce({ schema_version: "v1", tenant_id: "t1", count: 0, next_offset: null, blueprints: [] });
    render(<BlueprintsPage />);
    await waitFor(() => expect(screen.getByText("No AI-system blueprints yet")).toBeInTheDocument());
    const seedButtons = screen.getAllByText("Seed from role archetypes");
    const seedButton = seedButtons.at(-1);
    if (!seedButton) throw new Error("expected a blueprint seed action");
    fireEvent.click(seedButton);
    await waitFor(() => expect(apiMock.seedBlueprints).toHaveBeenCalled());
  });

  it("hides approval from a non-admin role (RBAC gate)", async () => {
    render(<BlueprintsPage />);
    await waitFor(() => expect(screen.getByText("Developer")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("blueprint-row-bp_seed_developer"));
    // Drawer loads the pending version; analyst sees a disabled Approve button.
    const approve = await screen.findByRole("button", { name: /approve/i });
    expect(approve).toBeDisabled();
    expect(screen.getByText("Approval requires an admin (governance) role.")).toBeInTheDocument();
  });

  it("lets an admin approve a pending version", async () => {
    authMock.capabilities = ["inventory.read", "scan.run", "policy.manage"];
    apiMock.approveBlueprintVersion.mockResolvedValue({ version: { status: "approved" } });
    render(<BlueprintsPage />);
    await waitFor(() => expect(screen.getByText("Developer")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("blueprint-row-bp_seed_developer"));
    const approve = await screen.findByRole("button", { name: /approve/i });
    expect(approve).not.toBeDisabled();
    fireEvent.click(approve);
    await waitFor(() => expect(apiMock.approveBlueprintVersion).toHaveBeenCalledWith("bp_seed_developer", 1));
  });
});
