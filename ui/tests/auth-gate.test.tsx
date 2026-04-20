import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, afterEach } from "vitest";

import { AuthGate } from "@/components/auth-gate";
import { clearSessionApiKey, setSessionApiKey } from "@/lib/auth";

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  clearSessionApiKey();
  vi.restoreAllMocks();
});

describe("AuthGate", () => {
  it("renders protected content when auth is not required", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: () => Promise.resolve({
        authenticated: false,
        auth_required: false,
        configured_modes: [],
        recommended_ui_mode: "no_auth",
        auth_method: null,
        subject: null,
        role: null,
        tenant_id: "default",
        oidc_issuer_suffix: null,
        api_key_id_prefix: null,
        request_id: null,
        trace_id: null,
        span_id: null,
      }),
    }) as typeof fetch;

    render(
      <AuthGate>
        <div>protected surface</div>
      </AuthGate>,
    );

    await waitFor(() => expect(screen.getByText("protected surface")).toBeInTheDocument());
  });

  it("shows the session API key fallback when the API returns 401", async () => {
    setSessionApiKey("stale-key")
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: () => Promise.resolve({ detail: "Unauthorized — invalid API key" }),
    }) as typeof fetch;

    render(
      <AuthGate>
        <div>protected surface</div>
      </AuthGate>,
    );

    await waitFor(() => expect(screen.getByText("Control-plane authentication required")).toBeInTheDocument());
    expect(screen.getByDisplayValue("stale-key")).toBeInTheDocument();
  });
});
