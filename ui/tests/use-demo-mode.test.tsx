import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useDemoMode } from "@/hooks/use-demo-mode";

const { apiMock, authState } = vi.hoisted(() => ({
  apiMock: { health: vi.fn() },
  authState: {
    loading: false,
    session: {
      authenticated: true,
      auth_required: false,
      configured_modes: [],
      recommended_ui_mode: "no_auth",
      auth_method: "anonymous",
      subject: "anonymous",
    },
  },
}));

vi.mock("@/lib/api", () => ({ api: apiMock }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => authState }));

describe("useDemoMode", () => {
  beforeEach(() => {
    apiMock.health.mockReset();
  });

  it("recognizes the server-issued anonymous viewer used by the public demo", async () => {
    apiMock.health.mockResolvedValue({
      status: "ok",
      version: "0.101.0",
      auth_required: false,
      auth_configured: false,
      unauthenticated_allowed: true,
    });

    const { result } = renderHook(() => useDemoMode());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.isDemoMode).toBe(true);
  });
});
