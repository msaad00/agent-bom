import { render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SelfPosturePage from "@/app/self-posture/page";
import type { SelfPostureReport } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getSelfPosture: vi.fn(),
  },
}));

vi.mock("next/link", () => ({
  default: ({ href, children }: { href: string; children: ReactNode }) => <a href={href}>{children}</a>,
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    api: apiMock,
  };
});

function report(overrides: Partial<SelfPostureReport> = {}): SelfPostureReport {
  return {
    schema_version: 1,
    overall_status: "hardened",
    hardened: true,
    deployment_env: "production",
    counts: { pass: 3, fail: 0, warn: 0, unknown: 0 },
    checks: [
      {
        id: "auth.api_authentication",
        category: "auth",
        title: "API authentication enforced",
        status: "pass",
        detail: "Unauthenticated API access is disabled.",
        remediation: "",
      },
    ],
    ...overrides,
  };
}

describe("SelfPosturePage", () => {
  beforeEach(() => {
    apiMock.getSelfPosture.mockReset();
  });

  it("shows a loading state while the report resolves", () => {
    apiMock.getSelfPosture.mockReturnValue(new Promise(() => {}));
    render(<SelfPosturePage />);
    expect(screen.getByTestId("self-posture-loading")).toBeInTheDocument();
  });

  it("renders the hardened headline from the API overall_status", async () => {
    apiMock.getSelfPosture.mockResolvedValue(report());
    render(<SelfPosturePage />);
    const headline = await screen.findByTestId("self-posture-headline");
    expect(headline).toHaveAttribute("data-overall", "hardened");
    expect(headline).toHaveTextContent(/hardened/i);
    // A pass check reads as pass.
    const check = screen.getByTestId("posture-check-auth.api_authentication");
    expect(within(check).getByTestId("posture-check-status")).toHaveTextContent(/pass/i);
  });

  it("reads clearly as a failure when a check is fail (never 'hardened')", async () => {
    apiMock.getSelfPosture.mockResolvedValue(
      report({
        overall_status: "at_risk",
        hardened: false,
        counts: { pass: 1, fail: 1, warn: 0, unknown: 0 },
        checks: [
          {
            id: "auth.api_authentication",
            category: "auth",
            title: "API authentication enforced",
            status: "fail",
            detail: "Unauthenticated API is enabled in production.",
            remediation: "Unset AGENT_BOM_ALLOW_UNAUTHENTICATED_API.",
          },
        ],
      })
    );
    render(<SelfPosturePage />);
    const headline = await screen.findByTestId("self-posture-headline");
    expect(headline).toHaveAttribute("data-overall", "at_risk");
    expect(headline).toHaveTextContent(/at risk/i);
    expect(headline).not.toHaveTextContent(/hardened/i);

    const chip = within(
      screen.getByTestId("posture-check-auth.api_authentication")
    ).getByTestId("posture-check-status");
    expect(chip).toHaveAttribute("data-status", "fail");
    expect(chip).toHaveTextContent(/fail/i);
    expect(chip).not.toHaveTextContent(/pass/i);
  });

  it("renders an unknown check as an explicit neutral 'not evaluated', never implied pass", async () => {
    apiMock.getSelfPosture.mockResolvedValue(
      report({
        overall_status: "needs_review",
        hardened: false,
        counts: { pass: 0, fail: 0, warn: 0, unknown: 1 },
        checks: [
          {
            id: "database.rls_isolation",
            category: "database",
            title: "Tenant isolation enforced by the database",
            status: "unknown",
            detail: "Configuration alone cannot prove the active role is non-superuser.",
            remediation: "Verify the active database role against the running database.",
          },
        ],
      })
    );
    render(<SelfPosturePage />);
    await screen.findByTestId("self-posture-headline");
    const chip = within(
      screen.getByTestId("posture-check-database.rls_isolation")
    ).getByTestId("posture-check-status");
    expect(chip).toHaveAttribute("data-status", "unknown");
    expect(chip).toHaveTextContent(/not evaluated/i);
    expect(chip).not.toHaveTextContent(/pass/i);
  });

  it("shows an error state that points at the CLI/API equivalent", async () => {
    apiMock.getSelfPosture.mockRejectedValue(new Error("boom"));
    render(<SelfPosturePage />);
    await waitFor(() => expect(screen.getByTestId("self-posture-error")).toBeInTheDocument());
    expect(screen.getByTestId("self-posture-error")).toHaveTextContent(/self-audit/i);
  });
});
