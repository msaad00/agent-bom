import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { KeyLifecyclePanel } from "@/components/key-lifecycle-panel";
import type { ApiKeyRecord, AuthPolicyResponse } from "@/lib/api";

const policy: AuthPolicyResponse = {
  api_key: {
    default_ttl_seconds: 3600,
    max_ttl_seconds: 86400,
    default_overlap_seconds: 900,
    max_overlap_seconds: 3600,
    rotation_policy: "enforced",
    rotation_endpoint: "/v1/auth/keys/{key_id}/rotate",
  },
  rate_limit_key: {
    status: "ok",
    last_rotated: null,
    age_days: null,
  },
  ui: {
    recommended_mode: "reverse_proxy_oidc",
    configured_modes: ["trusted_proxy", "api_key"],
    session_storage_fallback: "session_api_key",
    credentials_mode: "include",
    trusted_proxy_headers: ["X-Agent-Bom-Role", "X-Agent-Bom-Tenant-ID"],
    message: "Recommended browser auth is same-origin reverse-proxy OIDC.",
  },
  rate_limit_runtime: {
    backend: "postgres",
    postgres_configured: true,
    configured_api_replicas: 2,
    shared_required: true,
    shared_across_replicas: true,
    fail_closed: true,
    message: "Shared rate limiting is enabled across replicas.",
  },
  tenant_quotas: {
    active_scan_jobs: 10,
    retained_scan_jobs: 100,
    fleet_agents: 5000,
    schedules: 25,
  },
};

const keys: ApiKeyRecord[] = [
  {
    key_id: "key-1",
    key_prefix: "ab12cd34",
    name: "ci-service",
    role: "admin",
    created_at: "2026-04-23T00:00:00Z",
    expires_at: null,
    scopes: [],
    tenant_id: "default",
    revoked_at: null,
    rotation_overlap_until: null,
    replacement_key_id: null,
    state: "active",
    overlap_seconds_remaining: null,
  },
];

describe("KeyLifecyclePanel", () => {
  it("renders operator guidance, quota guardrails, and revocation boundaries", () => {
    render(
      <KeyLifecyclePanel
        loading={false}
        error={null}
        policy={policy}
        keys={keys}
        onRefresh={vi.fn()}
        roleLabel="Admin"
      />
    );

    expect(screen.getByText("Operator guidance")).toBeInTheDocument();
    expect(screen.getByText("Recommended: Reverse Proxy OIDC")).toBeInTheDocument();
    expect(screen.getByText("Runtime rate-limit backend")).toBeInTheDocument();
    expect(screen.getByText("Tenant guardrails")).toBeInTheDocument();
    expect(screen.getByText("Active scan jobs")).toBeInTheDocument();
    expect(screen.getByText("5000")).toBeInTheDocument();
    expect(screen.getByText("Revocation boundaries")).toBeInTheDocument();
    expect(screen.getByText("Reverse-proxy or OIDC sessions")).toBeInTheDocument();
  });
});
