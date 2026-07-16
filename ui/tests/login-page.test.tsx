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
    expect(screen.queryByRole("link", { name: /sign in with sso/i })).not.toBeInTheDocument();
    // First-run help points operators at the env var, no raw mode identifiers leak.
    expect(screen.getByText("AGENT_BOM_API_KEYS")).toBeInTheDocument();
    expect(screen.queryByText("Configured auth modes")).not.toBeInTheDocument();
    expect(screen.queryByText("session_api_key")).not.toBeInTheDocument();
  });

  it("shows Sign in with SSO when browser OIDC is configured", async () => {
    apiMock.getAuthMe.mockReset();
    apiMock.getAuthMe.mockResolvedValue({
      authenticated: false,
      auth_required: true,
      configured_modes: ["oidc_browser", "oidc_bearer", "api_key"],
      recommended_ui_mode: "oidc_browser",
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

    const ssoLink = await screen.findByRole("link", { name: /sign in with sso/i });
    expect(ssoLink).toHaveAttribute("href", "/v1/auth/oidc/login");
    expect(screen.getByText("Sign in with SSO, or use an API key as a fallback.")).toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(
      screen.queryByText("Single sign-on is handled by your identity provider or reverse proxy."),
    ).not.toBeInTheDocument();
  });

  it("brands the SSO button with the configured provider (Okta)", async () => {
    apiMock.getAuthMe.mockReset();
    apiMock.getAuthMe.mockResolvedValue({
      authenticated: false,
      auth_required: true,
      configured_modes: ["oidc_browser", "oidc_bearer", "api_key"],
      recommended_ui_mode: "oidc_browser",
      sso_provider: "okta",
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

    const ssoLink = await screen.findByRole("link", { name: /sign in with okta/i });
    expect(ssoLink).toHaveAttribute("href", "/v1/auth/oidc/login");
    expect(screen.getByText("Sign in with Okta, or use an API key as a fallback.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /sign in with sso/i })).not.toBeInTheDocument();
    // API-key fallback stays available and unchanged.
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
  });

  it("brands the SSO button for Microsoft Entra", async () => {
    apiMock.getAuthMe.mockReset();
    apiMock.getAuthMe.mockResolvedValue({
      authenticated: false,
      auth_required: true,
      configured_modes: ["oidc_browser", "api_key"],
      recommended_ui_mode: "oidc_browser",
      sso_provider: "entra",
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

    const ssoLink = await screen.findByRole("link", { name: /sign in with microsoft/i });
    expect(ssoLink).toHaveAttribute("href", "/v1/auth/oidc/login");
  });

  it("shows the reverse-proxy SSO hint (no fake button) when trusted_proxy is configured", async () => {
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
      expect(
        screen.getByText("Single sign-on is handled by your reverse proxy. Continue there, or use an API key below."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("link", { name: /sign in with sso/i })).not.toBeInTheDocument();
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
