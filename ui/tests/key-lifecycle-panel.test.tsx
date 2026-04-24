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
    last_rotated: "2026-04-20T00:00:00Z",
    age_days: 4,
    rotation_days: 30,
    max_age_days: 90,
    message: "Rate-limit key is 4 days old; rotation interval is 30 days.",
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
      rotation_tracking_supported: true,
      rotation_status: "ok",
      rotation_method: "env_swap_and_restart",
      rotation_days: 90,
      max_age_days: 180,
      last_rotated: "2026-04-01T00:00:00Z",
      age_days: 23,
      rotation_message: "Audit HMAC secret is 23 days old; configured rotation interval is 90 days.",
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
      rotation_tracking_supported: true,
      rotation_status: "rotation_due",
      rotation_method: "env_swap_and_restart",
      rotation_days: 30,
      max_age_days: 180,
      last_rotated: "2026-03-10T00:00:00Z",
      age_days: 45,
      rotation_message: "Compliance signing key is 45 days old, past the configured rotation interval (30 days).",
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
    source: "global_default",
    per_tenant_overrides: true,
    active_override: false,
    override_endpoint: "/v1/auth/quota",
    message: "Tenant quotas resolve from global defaults. Tenant-specific overrides can be configured when needed.",
    overrides: {},
    usage: {
      active_scan_jobs: { limit: 10, default_limit: 10, override_limit: null, current: 2, remaining: 8, enforced: true, source: "global_default" },
      retained_scan_jobs: { limit: 100, default_limit: 100, override_limit: null, current: 12, remaining: 88, enforced: true, source: "global_default" },
      fleet_agents: { limit: 5000, default_limit: 5000, override_limit: null, current: 48, remaining: 4952, enforced: true, source: "global_default" },
      schedules: { limit: 25, default_limit: 25, override_limit: null, current: 3, remaining: 22, enforced: true, source: "global_default" },
    },
  },
  identity_provisioning: {
    oidc: {
      supported: true,
      configured: true,
      mode: "single_issuer",
      issuer_hosts: ["login.example.com"],
      provider_count: 1,
      audience_configured: true,
      role_claim: "agent_bom_role",
      tenant_claim: "tenant_id",
      require_role_claim: true,
      require_tenant_claim: true,
      allow_default_tenant: false,
      required_nonce: false,
      message: "OIDC bearer auth is enabled for a single issuer.",
    },
    saml: {
      supported: true,
      configured: true,
      metadata_endpoint: "/v1/auth/saml/metadata",
      acs_path: "/v1/auth/saml/login",
      idp_host: "idp.example.com",
      role_attribute: "agent_bom_role",
      tenant_attribute: "tenant_id",
      require_role_attribute: false,
      require_tenant_attribute: false,
      session_ttl_seconds: 3600,
      message: "SAML assertion exchange is enabled and mints short-lived session API keys after IdP verification.",
    },
    scim: {
      supported: true,
      configured: true,
      status: "configured",
      base_path: "/scim/v2",
      token_configured: true,
      external_id_attribute: "externalId",
      role_attribute: "agent_bom_role",
      tenant_attribute: "tenant_id",
      groups_required: false,
      message: "SCIM provisioning bootstrap is configured.",
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
    expect(screen.getAllByText("Active scan jobs").length).toBeGreaterThan(0);
    expect(screen.getByText("5000")).toBeInTheDocument();
    expect(screen.getByText("Current 48 · Remaining 4952")).toBeInTheDocument();
    expect(screen.getByText("Override management")).toBeInTheDocument();
    expect(screen.getByText("Manage overrides at /v1/auth/quota.")).toBeInTheDocument();
    expect(screen.getAllByText("Global default").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Save overrides" })).toBeInTheDocument();
    expect(screen.getByText("Secret and integrity posture")).toBeInTheDocument();
    expect(screen.getByText("Audit HMAC")).toBeInTheDocument();
    expect(screen.getByText("Compliance evidence signing")).toBeInTheDocument();
    expect(
      screen.getByText("Ed25519 · asymmetric public key · key deadbeefcafebabe · /v1/compliance/verification-key")
    ).toBeInTheDocument();
    expect(screen.getByText("Rotation posture")).toBeInTheDocument();
    expect(screen.getByText("Service API keys")).toBeInTheDocument();
    expect(screen.getByText("Rate-limit key")).toBeInTheDocument();
    expect(screen.getByText("Audit HMAC rotation")).toBeInTheDocument();
    expect(screen.getByText("Compliance signing rotation")).toBeInTheDocument();
    expect(screen.getByText("enforced · 15m default overlap · /v1/auth/keys/{key_id}/rotate")).toBeInTheDocument();
    expect(screen.getByText("Rate-limit key is 4 days old; rotation interval is 30 days.")).toBeInTheDocument();
    expect(screen.getByText("Audit HMAC secret is 23 days old; configured rotation interval is 90 days.")).toBeInTheDocument();
    expect(
      screen.getByText("Compliance signing key is 45 days old, past the configured rotation interval (30 days).")
    ).toBeInTheDocument();
    expect(screen.getAllByText(/env swap and restart/).length).toBeGreaterThan(0);
    expect(screen.getByText("Identity lifecycle")).toBeInTheDocument();
    expect(screen.getByText("OIDC browser / bearer")).toBeInTheDocument();
    expect(screen.getByText("SAML assertion exchange")).toBeInTheDocument();
    expect(screen.getByText("SCIM provisioning")).toBeInTheDocument();
    expect(screen.getByText("configured · /scim/v2 · token configured")).toBeInTheDocument();
    expect(screen.getByText("Role agent_bom_role · tenant tenant_id · external ID externalId")).toBeInTheDocument();
    expect(screen.getByText("Revocation boundaries")).toBeInTheDocument();
    expect(screen.getByText("OIDC or reverse-proxy browser sessions must be terminated at the upstream identity provider or trusted proxy.")).toBeInTheDocument();
  });
});
