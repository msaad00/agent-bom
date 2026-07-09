import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/components/auth-provider";
import { DemoConnectCard, DemoModeBanner } from "@/components/demo-mode-cta";

const originalFetch = global.fetch;

interface Scenario {
  unauthenticated_allowed: boolean;
  auth_configured: boolean;
  authenticated: boolean;
}

function mockServer(scenario: Scenario) {
  global.fetch = vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    const json = (body: unknown) =>
      Promise.resolve({
        ok: true,
        status: 200,
        statusText: "OK",
        json: () => Promise.resolve(body),
      });

    if (url.includes("/health")) {
      return json({
        status: "ok",
        version: "0.0.0-test",
        auth_required: !scenario.unauthenticated_allowed || scenario.auth_configured,
        auth_configured: scenario.auth_configured,
        configured_auth_modes: scenario.auth_configured ? ["api_key"] : [],
        unauthenticated_allowed: scenario.unauthenticated_allowed,
      });
    }

    if (url.includes("/v1/auth/me")) {
      return json({
        authenticated: scenario.authenticated,
        auth_required: !scenario.unauthenticated_allowed || scenario.auth_configured,
        configured_modes: scenario.auth_configured ? ["api_key"] : [],
        recommended_ui_mode: scenario.authenticated ? "authenticated" : "no_auth",
        auth_method: scenario.authenticated ? "api_key" : null,
        subject: scenario.authenticated ? "user@example.com" : null,
        tenant_id: "default",
        role: scenario.authenticated ? "admin" : null,
        role_summary: null,
        memberships: [],
        request_id: null,
        trace_id: null,
        span_id: null,
      });
    }

    return json({});
  }) as unknown as typeof fetch;
}

afterEach(() => {
  global.fetch = originalFetch;
  window.__AGENT_BOM_CONFIG__ = undefined;
  vi.restoreAllMocks();
});

describe("DemoModeBanner", () => {
  it("shows the connect-your-cloud CTA in public demo mode", async () => {
    mockServer({ unauthenticated_allowed: true, auth_configured: false, authenticated: false });

    render(
      <AuthProvider>
        <DemoModeBanner />
      </AuthProvider>,
    );

    const cta = await screen.findByRole("link", { name: /sign in \/ get started/i });
    expect(cta).toBeInTheDocument();
    expect(cta).toHaveAttribute("href", "/login");
    expect(screen.getByTestId("demo-mode-banner")).toBeInTheDocument();
  });

  it("honors a configured sign-in URL", async () => {
    mockServer({ unauthenticated_allowed: true, auth_configured: false, authenticated: false });
    window.__AGENT_BOM_CONFIG__ = { signInUrl: "https://app.example.com/start" };

    render(
      <AuthProvider>
        <DemoModeBanner />
      </AuthProvider>,
    );

    const cta = await screen.findByRole("link", { name: /sign in \/ get started/i });
    expect(cta).toHaveAttribute("href", "https://app.example.com/start");
  });

  it("stays hidden for an authenticated deployment", async () => {
    mockServer({ unauthenticated_allowed: false, auth_configured: true, authenticated: true });

    render(
      <AuthProvider>
        <DemoModeBanner />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.queryByTestId("demo-mode-banner")).not.toBeInTheDocument());
  });

  it("stays hidden for a signed-in viewer even when the server allows anonymous access", async () => {
    mockServer({ unauthenticated_allowed: true, auth_configured: false, authenticated: true });

    render(
      <AuthProvider>
        <DemoModeBanner />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.queryByTestId("demo-mode-banner")).not.toBeInTheDocument());
  });
});

describe("DemoConnectCard", () => {
  it("renders the connect-surface demo state in demo mode", async () => {
    mockServer({ unauthenticated_allowed: true, auth_configured: false, authenticated: false });

    render(
      <AuthProvider>
        <DemoConnectCard />
      </AuthProvider>,
    );

    expect(await screen.findByTestId("demo-connect-card")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /connect your cloud/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /connect your cloud/i })).toHaveAttribute("href", "/login");
  });

  it("is absent outside demo mode", async () => {
    mockServer({ unauthenticated_allowed: false, auth_configured: true, authenticated: true });

    render(
      <AuthProvider>
        <DemoConnectCard />
      </AuthProvider>,
    );

    await waitFor(() => expect(screen.queryByTestId("demo-connect-card")).not.toBeInTheDocument());
  });
});
