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
  audit_hmac: {
    status: "configured",
    configured: true,
    key_id_configured: true,
    rotation_tracking_supported: true,
  },
  ui: {
    recommended_mode: "reverse_proxy_oidc",
    configured_modes: ["trusted_proxy", "api_key"],
    browser_session: "signed_http_only_cookie",
    session_storage_fallback: "disabled",
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
      active_scan_jobs: { limit: 10, default_limit: 10, override_limit: null, current: 2, remaining: 8, enforced: true, source: "global_default", utilization_pct: 20, status: "ok", recommended_action: "Usage is within the enforced tenant quota." },
      retained_scan_jobs: { limit: 100, default_limit: 100, override_limit: null, current: 12, remaining: 88, enforced: true, source: "global_default", utilization_pct: 12, status: "ok", recommended_action: "Usage is within the enforced tenant quota." },
      fleet_agents: { limit: 5000, default_limit: 5000, override_limit: null, current: 48, remaining: 4952, enforced: true, source: "global_default", utilization_pct: 1, status: "ok", recommended_action: "Usage is within the enforced tenant quota." },
      schedules: { limit: 25, default_limit: 25, override_limit: null, current: 3, remaining: 22, enforced: true, source: "global_default", utilization_pct: 12, status: "ok", recommended_action: "Usage is within the enforced tenant quota." },
    },
  },
  data_access_boundaries: {
    default_posture: {
      self_hosted_first: true,
      mandatory_hosted_control_plane: false,
      hidden_telemetry: false,
      default_network_mode: "operator_controlled",
      credential_values_stored: false,
      credential_values_transmitted: false,
      credential_values_validated_by_default: false,
      support_access_default: "customer_selected",
    },
    modes: [
      {
        mode: "local_discovery",
        reads: ["known_agent_mcp_config_paths", "env_var_names"],
        does_not_read: ["env_var_values", "arbitrary_personal_files"],
        operator_controls: ["--dry-run", "--offline"],
      },
      {
        mode: "project_scan",
        reads: ["operator_selected_project_scope"],
        does_not_store: ["matched_secret_value", "matched_secret_prefix"],
        operator_controls: ["--project", "--no-skill"],
      },
      {
        mode: "cloud_inventory",
        reads: ["metadata_available_to_operator_provided_identity"],
        required_identity: "read_only",
        does_not_do: ["mutate_cloud_resources", "use_discovered_credentials"],
        operator_controls: ["provider_flags", "--dry-run"],
      },
    ],
    network_boundaries: {
      telemetry: "none",
      vulnerability_enrichment: "operator_controlled",
      cloud_provider_api_calls: "operator_credentials_only",
      outbound_exports: "opt_in_only",
      proxy_gateway_egress: "policy_controlled",
      disable_controls: ["--offline", "--no-scan", "--sandbox-egress deny"],
    },
    storage_boundaries: {
      local_default: "local_files_and_stdout_only",
      control_plane_default: "tenant_scoped_database_records",
      secret_values: "never_stored",
      secret_previews: "never_stored",
      raw_artifact_exports: "operator_opt_in",
      support_bundle_default: "customer_selected_redacted_evidence",
    },
    auth_boundaries: {
      api: ["api_key", "oidc_bearer", "saml_session_key", "trusted_reverse_proxy"],
      authorization: ["rbac_role", "tenant_scope", "admin_required_for_key_lifecycle"],
      scim: {
        provisioning_authority: "scim_lifecycle_store",
        runtime_auth_overlay: "enabled_when_configured",
        tenant_source: "AGENT_BOM_SCIM_TENANT_ID",
        payload_tenant_attributes_ignored: true,
      },
      does_not_do: ["accept_untrusted_payload_tenant", "cross_tenant_lookup_without_auth_context"],
    },
    deployment_boundaries: {
      local: ["explicit_project_or_config_scope", "offline_mode_available"],
      endpoint: ["mdm_command_scope", "fleet_summary_sync"],
      eks: ["network_policy", "read_only_cloud_identity"],
      gateway: ["explicit_mcp_proxy_path", "policy_reload"],
    },
    extension_boundaries: {
      connectors: {
        default_posture: "agentless_read_only",
        credential_scope: "operator_provided_connector_identity",
        does_not_do: ["write_remote_systems", "escalate_permissions", "reuse_discovered_credentials"],
        stronger_actions_require: ["explicit_connector_config", "rbac_permission", "audit_event"],
      },
      plugins_and_skills: {
        default_posture: "disabled_until_scoped_by_operator",
        execution_boundary: "selected_path_or_registry_entry",
        does_not_do: ["silent_install", "unscoped_filesystem_read", "unapproved_network_export"],
        controls: ["--no-skill", "--skill-only", "signed_skill_verification"],
      },
      roles: {
        viewer: ["read_allowed_tenant_evidence"],
        analyst: ["run_scans", "review_findings", "operate_non_admin_workflows"],
        admin: ["manage_keys", "manage_policy", "manage_tenant_settings"],
        principle: "least_privilege_by_default",
      },
    },
    posture_vocabulary: {
      capability_flags: ["rotation_tracking_supported"],
      enforcement_flags: ["runtime_auth_enforced", "mtls_enforced"],
      intentional_boundary_flags: ["payload_tenant_attributes_ignored"],
    },
    operator_controls: {
      scope_preview: "agent-bom agents --dry-run",
      inventory_only: "--inventory <file>",
      project_scope: "--project <dir>",
      config_scope: "--config-dir <dir>",
      disable_vulnerability_network: "--offline",
      disable_scan_network_and_vuln_lookup: "--no-scan",
      disable_skill_scan: "--no-skill",
      isolate_skill_scan: "--skill-only",
      api_access_control: ["api_keys", "rbac_roles", "tenant_scope", "trusted_proxy_attestation"],
      optional_exports: ["siem", "otel", "slack"],
    },
    credential_evidence: {
      config_env_vars: "names_only",
      project_secret_scan: "redacted_labels_only",
      stores_matched_value: false,
      stores_matched_prefix: false,
      validates_live_secret: false,
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
      default_role: "viewer",
      role_values: ["admin", "analyst", "viewer"],
      tenant_attribute: "tenant_id",
      tenant_assignment: {
        source: "AGENT_BOM_SCIM_TENANT_ID",
        payload_tenant_attributes_ignored: true,
      },
      provisioning_authority: "scim_lifecycle_store",
      auth_authority: "api_key_oidc_saml_or_trusted_proxy",
      runtime_auth_enforced: false,
      deprovisioning_boundary: "SCIM deactivate/delete updates provisioned lifecycle state and audit evidence.",
      groups_required: false,
      verified_idp_templates: [
        { idp: "okta", status: "contract_tested", notes: "Okta lifecycle payloads are covered." },
        { idp: "microsoft_entra_id", status: "contract_tested", notes: "Entra lifecycle payloads are covered." },
        { idp: "google_cloud_identity", status: "contract_tested", notes: "Google lifecycle payloads are covered." },
      ],
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
    expect(screen.getAllByText("ok").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Usage is within the enforced tenant quota.").length).toBeGreaterThan(0);
    expect(screen.getByText("Override management")).toBeInTheDocument();
    expect(screen.getByText("Manage overrides at /v1/auth/quota.")).toBeInTheDocument();
    expect(screen.getAllByText("Global default").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Save overrides" })).toBeInTheDocument();
    expect(screen.getByText("Data access boundaries")).toBeInTheDocument();
    expect(screen.getByText("Credential evidence")).toBeInTheDocument();
    expect(screen.getByText("Network and exports")).toBeInTheDocument();
    expect(screen.getByText(/Telemetry is none/)).toBeInTheDocument();
    expect(screen.getByText(/value stored false/)).toBeInTheDocument();
    expect(screen.getByText(/SCIM tenant AGENT_BOM_SCIM_TENANT_ID/)).toBeInTheDocument();
    expect(screen.getByText("local discovery")).toBeInTheDocument();
    expect(screen.getByText(/Does not store: matched secret value/)).toBeInTheDocument();
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
    expect(
      screen.getByText(
        "Roles from agent_bom_role default to viewer; tenant assignment is bound to AGENT_BOM_SCIM_TENANT_ID. Payload tenant fields are ignored."
      )
    ).toBeInTheDocument();
    expect(screen.getByText("SCIM auth boundary")).toBeInTheDocument();
    expect(screen.getByText("scim_lifecycle_store · auth: api_key_oidc_saml_or_trusted_proxy · upstream enforced")).toBeInTheDocument();
    expect(screen.getByText("Revocation boundaries")).toBeInTheDocument();
    expect(screen.getByText("OIDC or reverse-proxy browser sessions must be terminated at the upstream identity provider or trusted proxy.")).toBeInTheDocument();
  });
});
