import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import LoginPage from "@/app/login/page";
import { AuthProvider } from "@/components/auth-provider";

const mockReplace = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace, push: vi.fn() }),
  usePathname: () => "/login",
  useSearchParams: () => new URLSearchParams("returnTo=%2Fconnections"),
}));

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getAuthMe: vi.fn(),
    createAuthSession: vi.fn(),
    deleteAuthSession: vi.fn(),
  },
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      ...apiMock,
    },
  };
});

describe("LoginPage", () => {
  beforeEach(() => {
    mockReplace.mockReset();
    apiMock.getAuthMe.mockReset();
    apiMock.createAuthSession.mockReset();
    apiMock.getAuthMe.mockResolvedValue({
      authenticated: false,
      auth_required: true,
      configured_modes: ["api_key"],
      recommended_ui_mode: "session_api_key",
      auth_method: null,
      subject: null,
      role: null,
      tenant_id: "default",
      role_summary: null,
      memberships: [],
      request_id: null,
      trace_id: null,
      span_id: null,
    });
    apiMock.createAuthSession.mockResolvedValue(undefined);
  });

  it("renders a single-purpose API-key sign-in surface", async () => {
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.getByText("Sign in to agent-bom")).toBeInTheDocument());
    expect(screen.getByText("Enter your API key to access the dashboard.")).toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    // First-run help points operators at the env var, no raw mode identifiers leak.
    expect(screen.getByText("AGENT_BOM_API_KEYS")).toBeInTheDocument();
    expect(screen.queryByText("Configured auth modes")).not.toBeInTheDocument();
    expect(screen.queryByText("session_api_key")).not.toBeInTheDocument();
  });

  it("shows the SSO-handled hint (no fake button) when a proxy/OIDC mode is configured", async () => {
    apiMock.getAuthMe.mockReset();
    apiMock.getAuthMe.mockResolvedValue({
      authenticated: false,
      auth_required: true,
      configured_modes: ["trusted_proxy", "api_key"],
      recommended_ui_mode: "reverse_proxy_oidc",
      auth_method: null,
      subject: null,
      role: null,
      tenant_id: "default",
      role_summary: null,
      memberships: [],
      request_id: null,
      trace_id: null,
      span_id: null,
    });

    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>,
    );

    await waitFor(() =>
      expect(screen.getByText("Single sign-on is handled by your identity provider or reverse proxy.")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: /continue with sso/i })).not.toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
  });

  it("shows a friendly message when the API key is rejected", async () => {
    apiMock.createAuthSession.mockRejectedValueOnce(new Error("401 Unauthorized"));

    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>,
    );

    fireEvent.change(await screen.findByLabelText("API key"), { target: { value: "abk_bad" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(screen.getByText("That API key wasn't accepted — check it and try again.")).toBeInTheDocument(),
    );
  });

  it("redirects to returnTo after a successful browser session exchange", async () => {
    apiMock.getAuthMe
      .mockResolvedValueOnce({
        authenticated: false,
        auth_required: true,
        configured_modes: ["api_key"],
        recommended_ui_mode: "session_api_key",
        auth_method: null,
        subject: null,
        role: null,
        tenant_id: "default",
        role_summary: null,
        memberships: [],
        request_id: null,
        trace_id: null,
        span_id: null,
      })
      .mockResolvedValueOnce({
        authenticated: true,
        auth_required: true,
        configured_modes: ["api_key"],
        recommended_ui_mode: "session_api_key",
        auth_method: "browser_session",
        subject: "runtime:admin",
        role: "admin",
        tenant_id: "default",
        role_summary: {
          role: "admin",
          ui_role: "administrator",
          display_name: "Administrator",
          capabilities: [],
          cannot_do: [],
        },
        memberships: [],
        request_id: null,
        trace_id: null,
        span_id: null,
      });

    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>,
    );

    fireEvent.change(await screen.findByLabelText("API key"), { target: { value: "abk_test" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(apiMock.createAuthSession).toHaveBeenCalledWith("abk_test"));
    await waitFor(() => expect(mockReplace).toHaveBeenCalledWith("/connections"));
  });
});
