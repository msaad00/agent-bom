/**
 * The offline report importer is mounted by `app/page.tsx`, inside `AuthGate`.
 * Every way the auth probe can fail replaces that content: a 401 redirects to
 * `/login`, and an unreachable API renders "Control plane unreachable". So the
 * one feature built for "no working backend" was the one feature a user with a
 * report file and no working auth could never reach.
 *
 * The gate now offers an explicit way through. It is opt-in — the default is
 * still to block, which `auth-gate.test.tsx` keeps guarding — and it grants no
 * data: every API call behind it fails exactly as before. What it grants is the
 * ability to render a report the user already has on disk.
 */
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "@/components/auth-gate";
import { AuthProvider } from "@/components/auth-provider";
import { clearSessionApiKey } from "@/lib/auth";
import {
  disableOfflineReportMode,
  enableOfflineReportMode,
  isOfflineReportMode,
} from "@/lib/offline-report-mode";

const mockReplace = vi.fn();
const mockPush = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: mockReplace, push: mockPush }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
}));

const originalFetch = global.fetch;

afterEach(() => {
  global.fetch = originalFetch;
  window.__AGENT_BOM_CONFIG__ = undefined;
  clearSessionApiKey();
  disableOfflineReportMode();
  mockReplace.mockReset();
  mockPush.mockReset();
  vi.restoreAllMocks();
});

function unreachableApi() {
  global.fetch = vi.fn().mockResolvedValue({
    ok: false,
    status: 503,
    statusText: "Service Unavailable",
    json: () => Promise.resolve({ detail: "503 Service Unavailable" }),
    headers: new Headers(),
    url: "/v1/auth/me",
  }) as typeof fetch;
}

function unauthenticatedApi() {
  global.fetch = vi.fn().mockResolvedValue({
    ok: false,
    status: 401,
    statusText: "Unauthorized",
    json: () => Promise.resolve({ detail: "Unauthorized — invalid API key" }),
  }) as typeof fetch;
}

function renderGate() {
  return render(
    <AuthProvider>
      <AuthGate>
        <div>page-level offline state</div>
      </AuthGate>
    </AuthProvider>,
  );
}

describe("offline report mode", () => {
  it("is off until the user asks for it", () => {
    expect(isOfflineReportMode()).toBe(false);
    enableOfflineReportMode();
    expect(isOfflineReportMode()).toBe(true);
    disableOfflineReportMode();
    expect(isOfflineReportMode()).toBe(false);
  });
});

describe("AuthGate offline escape hatch", () => {
  it("offers a way through when the control plane is unreachable", async () => {
    unreachableApi();
    renderGate();

    await waitFor(() =>
      expect(screen.getByText("Control plane unreachable")).toBeInTheDocument(),
    );
    // Blocked by default — the audit guard in auth-gate.test.tsx still holds.
    expect(screen.queryByText("page-level offline state")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /continue offline with a report file/i }),
    ).toBeInTheDocument();
  });

  it("renders the page once the user continues offline, so the importer mounts", async () => {
    unreachableApi();
    renderGate();

    const button = await screen.findByRole("button", {
      name: /continue offline with a report file/i,
    });
    await userEvent.click(button);

    expect(await screen.findByText("page-level offline state")).toBeInTheDocument();
  });

  it("stops bouncing an unauthenticated user back out to /login", async () => {
    unauthenticatedApi();
    act(() => {
      enableOfflineReportMode();
    });
    renderGate();

    expect(await screen.findByText("page-level offline state")).toBeInTheDocument();
    expect(mockReplace).not.toHaveBeenCalled();
  });

  it("says it is offline and offers the way back to signing in", async () => {
    unreachableApi();
    renderGate();

    await userEvent.click(
      await screen.findByRole("button", {
        name: /continue offline with a report file/i,
      }),
    );

    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent(/offline/i);

    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(isOfflineReportMode()).toBe(false);
    await waitFor(() =>
      expect(screen.queryByText("page-level offline state")).not.toBeInTheDocument(),
    );
  });
});
