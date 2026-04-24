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
  secret_integrity: {
    audit_hmac: {
      status: "configured",
      configured: true,
      required: false,
      source: "AGENT_BOM_AUDIT_HMAC_KEY",
      persists_across_restart: true,
      rotation_tracking_supported: false,
      message: "Audit log tamper detection uses a configured shared secret.",
    },
    compliance_signing: {
      algorithm: "Ed25519",
      mode: "asymmetric_public_key",
      configured: true,
      key_id: "deadbeefcafebabe",
      public_key_endpoint: "/v1/compliance/verification-key",
      auditor_distributable: true,
      uses_audit_hmac_secret: false,
      persists_across_restart: true,
      message: "Compliance evidence bundles are signed with Ed25519.",
    },
  },
  tenant_quotas: {
    active_scan_jobs: 10,
    retained_scan_jobs: 100,
    fleet_agents: 5000,
    schedules: 25,
  },
  tenant_quota_runtime: {
    source: "static_process_config",
    per_tenant_overrides: false,
    message: "Tenant quotas are enforced from control-plane configuration today.",
    usage: {
      active_scan_jobs: { limit: 10, current: 2, remaining: 8, enforced: true },
      retained_scan_jobs: { limit: 100, current: 12, remaining: 88, enforced: true },
      fleet_agents: { limit: 5000, current: 48, remaining: 4952, enforced: true },
      schedules: { limit: 25, current: 3, remaining: 22, enforced: true },
    },
  },
  identity_provisioning: {
    scim: {
      supported: false,
      configured: false,
      status: "not_implemented",
      message: "SCIM provisioning is not implemented yet.",
    },
    session_revocation: {
      service_keys: "API key revocation takes effect immediately at the control-plane auth layer.",
      session_api_key: "The browser fallback key is scoped to the current browser session.",
      browser_sessions: "OIDC or reverse-proxy browser sessions must be terminated at the upstream identity provider or trusted proxy.",
    },
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
    expect(screen.getByText("Current 48 · Remaining 4952")).toBeInTheDocument();
    expect(screen.getByText("Secret and integrity posture")).toBeInTheDocument();
    expect(screen.getByText("Audit HMAC")).toBeInTheDocument();
    expect(screen.getByText("Compliance evidence signing")).toBeInTheDocument();
    expect(
      screen.getByText("Ed25519 · asymmetric public key · key deadbeefcafebabe · /v1/compliance/verification-key")
    ).toBeInTheDocument();
    expect(screen.getByText("Identity lifecycle")).toBeInTheDocument();
    expect(screen.getByText("SCIM provisioning")).toBeInTheDocument();
    expect(screen.getByText("Revocation boundaries")).toBeInTheDocument();
    expect(screen.getByText("OIDC or reverse-proxy browser sessions must be terminated at the upstream identity provider or trusted proxy.")).toBeInTheDocument();
  });
});
