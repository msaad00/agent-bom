import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { WebhooksPanel } from "@/components/integrations/webhooks-panel";

const { apiMock, authMock } = vi.hoisted(() => ({
  apiMock: {
    listWebhookSubscriptions: vi.fn(),
    listWebhookOutbox: vi.fn(),
    createWebhookSubscription: vi.fn(),
    enableWebhookSubscription: vi.fn(),
    disableWebhookSubscription: vi.fn(),
    deleteWebhookSubscription: vi.fn(),
    testWebhookSubscription: vi.fn(),
  },
  authMock: { value: { session: { auth_required: true }, hasCapability: (c: string): boolean => c === "policy.manage" } },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => authMock.value }));

const SUB = {
  subscription_id: "wh-1",
  tenant_id: "t",
  url: "https://hooks.example.com/team/sensitive-path",
  event_types: ["drift.detected"],
  status: "active",
  description: "Ops channel",
  created_at: "2026-07-14T00:00:00Z",
  updated_at: "2026-07-14T00:00:00Z",
  allow_private_networks: false,
  secret_fingerprint: "test",
};

beforeEach(() => {
  Object.values(apiMock).forEach((fn) => fn.mockReset());
  authMock.value = { session: { auth_required: true }, hasCapability: (c: string): boolean => c === "policy.manage" };
  window.confirm = () => true;
  apiMock.listWebhookSubscriptions.mockResolvedValue({
    schema_version: "v1",
    tenant_id: "t",
    event_catalog: ["drift.detected", "budget.exceeded"],
    count: 1,
    subscriptions: [SUB],
  });
  apiMock.listWebhookOutbox.mockResolvedValue({
    schema_version: "v1",
    tenant_id: "t",
    status: null,
    count: 0,
    records: [],
    stats: { pending: 2, delivered: 5, dead_letter: 1 },
  });
});

describe("WebhooksPanel", () => {
  it("renders subscriptions and redacts the URL (never shows the secret path)", async () => {
    render(<WebhooksPanel />);
    expect(await screen.findByText("https://hooks.example.com/•••")).toBeInTheDocument();
    // The sensitive path segment must NOT be rendered anywhere.
    expect(screen.queryByText(/sensitive-path/)).not.toBeInTheDocument();
    // Only the fingerprint handle is shown.
    expect(screen.getByText("test…")).toBeInTheDocument();
  });

  it("creates a subscription and reveals the one-time signing secret", async () => {
    apiMock.createWebhookSubscription.mockResolvedValue({
      schema_version: "v1",
      subscription: SUB,
      signing_secret: "test",
      secret_notice: "store now",
    });
    render(<WebhooksPanel />);
    fireEvent.click(await screen.findByRole("button", { name: /New subscription/i }));
    fireEvent.change(screen.getByTestId("webhook-url-input"), {
      target: { value: "https://hooks.example.com/new" },
    });
    fireEvent.click(screen.getByTestId("webhook-create-submit"));

    await waitFor(() => expect(apiMock.createWebhookSubscription).toHaveBeenCalledTimes(1));
    expect(apiMock.createWebhookSubscription.mock.calls[0]![0]).toMatchObject({
      url: "https://hooks.example.com/new",
    });
    expect(await screen.findByTestId("webhook-secret-reveal")).toHaveTextContent("test");
  });

  it("wires enable/disable, test, and delete actions to their endpoints", async () => {
    apiMock.disableWebhookSubscription.mockResolvedValue({ schema_version: "v1", subscription: SUB });
    apiMock.testWebhookSubscription.mockResolvedValue({ schema_version: "v1", queued: true });
    apiMock.deleteWebhookSubscription.mockResolvedValue(undefined);

    render(<WebhooksPanel />);
    const row = (await screen.findByTestId("webhooks-table")).querySelector("tbody tr")!;
    const scope = within(row as HTMLElement);

    fireEvent.click(scope.getByRole("button", { name: /Test/i }));
    await waitFor(() => expect(apiMock.testWebhookSubscription).toHaveBeenCalledWith("wh-1"));

    fireEvent.click(scope.getByRole("button", { name: /Disable/i }));
    await waitFor(() => expect(apiMock.disableWebhookSubscription).toHaveBeenCalledWith("wh-1"));

    fireEvent.click(scope.getByRole("button", { name: /Delete/i }));
    await waitFor(() => expect(apiMock.deleteWebhookSubscription).toHaveBeenCalledWith("wh-1"));
  });

  it("shows an error state when the list fails", async () => {
    apiMock.listWebhookSubscriptions.mockRejectedValue(new Error("boom"));
    render(<WebhooksPanel />);
    expect(await screen.findByText(/Could not load webhook subscriptions/i)).toBeInTheDocument();
  });

  it("gates management actions for non-admin viewers", async () => {
    authMock.value = { session: { auth_required: true }, hasCapability: (): boolean => false };
    render(<WebhooksPanel />);
    expect(await screen.findByText(/Viewing only/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /New subscription/i })).toBeDisabled();
  });
});
