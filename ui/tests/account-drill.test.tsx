import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import AccountDrillPage from "@/app/accounts/[ref]/page";
import AccountDetailClient from "@/app/accounts/[ref]/AccountDetailClient";
import { api } from "@/lib/api";
import type { AccountSummaryResponse } from "@/lib/api-types";

vi.mock("next/navigation", () => ({
  useParams: () => ({ ref: "aws:111111111111" }),
}));

function emptySeverity() {
  return { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 };
}

function summary(overrides: Partial<AccountSummaryResponse> = {}): AccountSummaryResponse {
  return {
    schema_version: "cloud.account.summary.v1",
    tenant_id: "default",
    account_ref: "aws:111111111111",
    provider: "aws",
    account: "111111111111",
    regions: ["us-east-1"],
    environments: ["prod"],
    findings_total: 3,
    severity: { critical: 1, high: 1, medium: 1, low: 0, unrated: 0 },
    domains: [
      { domain: "cspm", label: "CSPM", count: 1, severity: { ...emptySeverity(), high: 1 }, href: "/findings?provider=aws&account=aws%3A111111111111&domain=cspm" },
      { domain: "vuln", label: "Vuln mgmt", count: 1, severity: { ...emptySeverity(), critical: 1 }, href: "/findings?provider=aws&account=aws%3A111111111111&domain=vuln" },
      { domain: "aspm", label: "ASPM", count: 0, severity: emptySeverity(), href: "/findings?provider=aws&account=aws%3A111111111111&domain=aspm" },
      { domain: "dspm", label: "DSPM", count: 0, severity: emptySeverity(), href: "/findings?provider=aws&account=aws%3A111111111111&domain=dspm" },
      { domain: "aispm", label: "AISPM", count: 1, severity: { ...emptySeverity(), medium: 1 }, href: "/findings?provider=aws&account=aws%3A111111111111&domain=aispm" },
    ],
    compliance: {
      evaluated: 10,
      passed: 8,
      failed: 2,
      pass_rate: 80.0,
      benchmarks: [{ provider: "aws", benchmark: "CIS AWS Foundations", passed: 8, failed: 2, evaluated: 10, pass_rate: 80.0 }],
      href: "/findings?provider=aws&account=aws%3A111111111111&domain=cspm",
    },
    assets: { count: 2, href: "/inventory/assets?provider=aws", note: "" },
    identities: { count: 0, roles: 1, note: "" },
    drill: { findings_href: "/findings?provider=aws&account=aws%3A111111111111", graph_href: "/graph?provider=aws" },
    truncated: false,
    empty: false,
    note: "",
    ...overrides,
  };
}

describe("AccountDrillPage", () => {
  it("renders header, all five domain lanes, and CIS pass-rate with drill links", async () => {
    vi.spyOn(api, "getCloudAccountSummary").mockResolvedValue(summary());
    render(<AccountDrillPage />);

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /AWS · 111111111111/i })).toBeInTheDocument();
    });
    // Five domain lanes, each drill-linked and pre-filtered by account.
    for (const label of ["CSPM", "Vuln mgmt", "ASPM", "DSPM", "AISPM"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    const cspmLane = screen.getByTestId("account-lane-cspm");
    expect(cspmLane).toHaveAttribute("href", expect.stringContaining("domain=cspm"));
    expect(cspmLane).toHaveAttribute("href", expect.stringContaining("account=aws%3A111111111111"));
    // Compliance health surfaces the stored pass-rate.
    expect(screen.getByText("80.0%")).toBeInTheDocument();
    expect(screen.getByText(/8 passed · 2 failed · 10 evaluated/)).toBeInTheDocument();
  });

  it("renders the client component directly from a ref read via useParams (static-export split)", async () => {
    // page.tsx is a server component (owns generateStaticParams for output:
    // export); the interactive body lives in AccountDetailClient, which reads
    // the ref from the URL at runtime. Rendering the client directly asserts
    // the split keeps the ref-driven render working.
    vi.spyOn(api, "getCloudAccountSummary").mockResolvedValue(summary());
    render(<AccountDetailClient />);
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /AWS · 111111111111/i })).toBeInTheDocument();
    });
    expect(api.getCloudAccountSummary).toHaveBeenCalledWith("aws:111111111111");
  });

  it("shows an honest empty state when the account has no evidence", async () => {
    vi.spyOn(api, "getCloudAccountSummary").mockResolvedValue(
      summary({ findings_total: 0, empty: true, compliance: { evaluated: 0, passed: 0, failed: 0, pass_rate: null, benchmarks: [], href: "/findings" } }),
    );
    render(<AccountDrillPage />);
    await waitFor(() => {
      expect(screen.getByText(/No evidence for this account yet/i)).toBeInTheDocument();
    });
  });
});
