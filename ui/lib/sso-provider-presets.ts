/**
 * IdP SSO provider presets for the enterprise auth setup surface.
 *
 * Mirrors the cloud connect wizard (`cloud-connect-wizard.ts`): a pure,
 * unit-tested catalog of provider metadata plus a small set of helpers that a
 * setup form consumes. Selecting a preset pre-fills the provider-specific
 * OIDC/SAML fields with the IdP's discovery-URL / issuer / endpoint shapes,
 * leaving `{placeholder}` tokens for the tenant-specific parts the customer
 * still supplies (their Okta domain, Entra tenant id, client id, …).
 *
 * Field keys and env vars map 1:1 onto the backend config dataclasses:
 *   - OIDC:  `OIDCConfig` / `OIDCBrowserConfig` (src/agent_bom/api/oidc.py,
 *            oidc_browser.py) — AGENT_BOM_OIDC_*
 *   - SAML:  `SAMLConfig` (src/agent_bom/api/saml.py) — AGENT_BOM_SAML_*
 *
 * Hard invariants (enforced by sso-provider-presets.test.ts):
 *   - A `secret`-kind field is NEVER prefilled — its `value` is always "".
 *   - "Generic" presets stay fully manual — every `value` is "".
 *   - Provider discovery-URL shapes track the current IdP docs (verified
 *     2026-07-14): Okta org vs `/oauth2/default`, Entra
 *     `login.microsoftonline.com/{tenantId}/v2.0`, Google `accounts.google.com`.
 */

export type SsoProtocol = "oidc" | "saml";

export type SsoProviderId =
  | "okta-oidc"
  | "entra-oidc"
  | "google-oidc"
  | "generic-oidc"
  | "okta-saml"
  | "entra-saml"
  | "google-saml"
  | "generic-saml";

/**
 * How a field is treated when a preset is applied:
 * - `config`  — provider-specific value the preset pre-fills (may contain
 *               `{placeholder}` tokens for the tenant-specific part).
 * - `tenant`  — the customer must supply it; the preset leaves `value` blank.
 * - `secret`  — sensitive; the customer must supply it; `value` is ALWAYS "".
 */
export type SsoFieldKind = "config" | "tenant" | "secret";

export interface SsoPresetField {
  /** Config attribute key (matches the backend dataclass field). */
  key: string;
  /** Environment variable the control plane reads. */
  envVar: string;
  label: string;
  kind: SsoFieldKind;
  /** Pre-filled value. Empty for `tenant`/`secret` and every generic field. */
  value: string;
  /** Guidance shown in the empty form input. */
  placeholder: string;
  hint?: string;
}

export interface SsoProviderPreset {
  id: SsoProviderId;
  /** Vendor name shown in the selector (e.g. "Okta"). */
  label: string;
  protocol: SsoProtocol;
  tagline: string;
  /** True for the manual, no-prefill Generic OIDC / Generic SAML presets. */
  generic: boolean;
  fields: SsoPresetField[];
  /** Ordered onboarding steps, mirroring the cloud wizard `setupSteps`. */
  setupSteps: string[];
  /** Doc reference for the provider setup. */
  docsHint: string;
}

// ── Shared field templates ──────────────────────────────────────────────────

/** Non-secret OIDC client fields the customer always supplies themselves. */
function oidcTenantClientFields(clientIdPlaceholder: string, audiencePlaceholder: string): SsoPresetField[] {
  return [
    {
      key: "audience",
      envVar: "AGENT_BOM_OIDC_AUDIENCE",
      label: "Audience (aud)",
      kind: "tenant",
      value: "",
      placeholder: audiencePlaceholder,
      hint: "Must equal the aud claim your IdP stamps on tokens for this app.",
    },
    {
      key: "client_id",
      envVar: "AGENT_BOM_OIDC_CLIENT_ID",
      label: "Client ID",
      kind: "tenant",
      value: "",
      placeholder: clientIdPlaceholder,
      hint: "The Application (client) ID from the IdP app registration.",
    },
    {
      key: "redirect_uri",
      envVar: "AGENT_BOM_OIDC_REDIRECT_URI",
      label: "Redirect URI",
      kind: "tenant",
      value: "",
      placeholder: "https://agent-bom.your-org.example/v1/auth/oidc/callback",
      hint: "Register this exact URL as an allowed redirect on the IdP app.",
    },
    {
      key: "client_secret",
      envVar: "AGENT_BOM_OIDC_CLIENT_SECRET",
      label: "Client secret",
      kind: "secret",
      value: "",
      placeholder: "Paste after creating the app — never committed, encrypted at rest",
      hint: "Confidential clients only. Stored server-side; never prefilled or logged.",
    },
  ];
}

/** SP-side SAML fields (agent-bom's own metadata) — same across every IdP. */
function samlServiceProviderFields(): SsoPresetField[] {
  return [
    {
      key: "sp_entity_id",
      envVar: "AGENT_BOM_SAML_SP_ENTITY_ID",
      label: "SP entity ID",
      kind: "config",
      value: "https://agent-bom.your-org.example/v1/auth/saml/metadata",
      placeholder: "https://agent-bom.your-org.example/v1/auth/saml/metadata",
      hint: "This deployment's SP entity ID — swap in your agent-bom host.",
    },
    {
      key: "sp_acs_url",
      envVar: "AGENT_BOM_SAML_SP_ACS_URL",
      label: "SP ACS URL",
      kind: "config",
      value: "https://agent-bom.your-org.example/v1/auth/saml/login",
      placeholder: "https://agent-bom.your-org.example/v1/auth/saml/login",
      hint: "Assertion Consumer Service URL the IdP posts the assertion to.",
    },
  ];
}

/** Role/tenant attribute mapping fields for SAML, defaulting to backend names. */
function samlAttributeFields(): SsoPresetField[] {
  return [
    {
      key: "role_attribute",
      envVar: "AGENT_BOM_SAML_ROLE_ATTRIBUTE",
      label: "Role attribute",
      kind: "config",
      value: "agent_bom_role",
      placeholder: "agent_bom_role",
      hint: "Configure the IdP to release an attribute of this name (admin/analyst/viewer).",
    },
    {
      key: "tenant_attribute",
      envVar: "AGENT_BOM_SAML_TENANT_ATTRIBUTE",
      label: "Tenant attribute",
      kind: "config",
      value: "tenant_id",
      placeholder: "tenant_id",
      hint: "Attribute carrying the tenant id for multi-tenant deployments.",
    },
  ];
}

function samlIdpCertField(): SsoPresetField {
  return {
    key: "idp_x509_cert",
    envVar: "AGENT_BOM_SAML_IDP_X509_CERT",
    label: "IdP signing certificate (X.509)",
    kind: "tenant",
    value: "",
    placeholder: "-----BEGIN CERTIFICATE-----\n… paste the IdP's public signing cert …",
    hint: "Public signing certificate downloaded from the IdP — not a secret, but you supply it.",
  };
}

// ── OIDC presets ────────────────────────────────────────────────────────────

const OKTA_OIDC: SsoProviderPreset = {
  id: "okta-oidc",
  label: "Okta",
  protocol: "oidc",
  tagline: "Okta OIDC via the default custom authorization server.",
  generic: false,
  docsHint: "Okta admin → Applications → Create App Integration → OIDC · Web.",
  fields: [
    {
      key: "issuer",
      envVar: "AGENT_BOM_OIDC_ISSUER",
      label: "Issuer",
      kind: "config",
      value: "https://{yourOktaDomain}/oauth2/default",
      placeholder: "https://your-org.okta.com/oauth2/default",
      hint: "Default custom auth server. Use https://{yourOktaDomain} alone for the org server.",
    },
    {
      key: "jwks_uri",
      envVar: "AGENT_BOM_OIDC_JWKS_URI",
      label: "JWKS URI",
      kind: "config",
      value: "https://{yourOktaDomain}/oauth2/default/v1/keys",
      placeholder: "https://your-org.okta.com/oauth2/default/v1/keys",
      hint: "Pin the JWKS URI (or allowlist the discovered value) for fail-closed discovery.",
    },
    {
      key: "scopes",
      envVar: "AGENT_BOM_OIDC_SCOPES",
      label: "Scopes",
      kind: "config",
      value: "openid profile email groups",
      placeholder: "openid profile email groups",
    },
    {
      key: "role_claim",
      envVar: "AGENT_BOM_OIDC_ROLE_CLAIM",
      label: "Role claim",
      kind: "config",
      value: "groups",
      placeholder: "groups",
      hint: "Add a groups claim to the Okta app and map group names to admin/analyst/viewer.",
    },
    {
      key: "tenant_claim",
      envVar: "AGENT_BOM_OIDC_TENANT_CLAIM",
      label: "Tenant claim",
      kind: "config",
      value: "tenant_id",
      placeholder: "tenant_id",
    },
    ...oidcTenantClientFields("0oabc1234DEF5678gh7", "api://default"),
  ],
  setupSteps: [
    "In Okta, create an OIDC Web app integration and note the client id + secret.",
    "Add https://<agent-bom-host>/v1/auth/oidc/callback as a sign-in redirect URI.",
    "Add a groups claim to the app so agent-bom can map roles from group membership.",
    "Set AGENT_BOM_OIDC_AUDIENCE to the token audience (api://default on the default server).",
  ],
};

const ENTRA_OIDC: SsoProviderPreset = {
  id: "entra-oidc",
  label: "Microsoft Entra ID",
  protocol: "oidc",
  tagline: "Entra ID (Azure AD) tenant-scoped v2.0 authority.",
  generic: false,
  docsHint: "Entra admin center → App registrations → New registration.",
  fields: [
    {
      key: "issuer",
      envVar: "AGENT_BOM_OIDC_ISSUER",
      label: "Issuer",
      kind: "config",
      value: "https://login.microsoftonline.com/{tenantId}/v2.0",
      placeholder: "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
      hint: "Use your Directory (tenant) ID. `organizations` disables single-tenant pinning.",
    },
    {
      key: "jwks_uri",
      envVar: "AGENT_BOM_OIDC_JWKS_URI",
      label: "JWKS URI",
      kind: "config",
      value: "https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys",
      placeholder: "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys",
    },
    {
      key: "scopes",
      envVar: "AGENT_BOM_OIDC_SCOPES",
      label: "Scopes",
      kind: "config",
      value: "openid profile email",
      placeholder: "openid profile email",
    },
    {
      key: "role_claim",
      envVar: "AGENT_BOM_OIDC_ROLE_CLAIM",
      label: "Role claim",
      kind: "config",
      value: "roles",
      placeholder: "roles",
      hint: "Define app roles in the Entra app registration; they surface in the roles claim.",
    },
    {
      key: "tenant_claim",
      envVar: "AGENT_BOM_OIDC_TENANT_CLAIM",
      label: "Tenant claim",
      kind: "config",
      value: "tid",
      placeholder: "tid",
      hint: "Entra stamps the directory id in the tid claim.",
    },
    ...oidcTenantClientFields("00001111-aaaa-2222-bbbb-3333cccc4444", "api://<application-client-id>"),
  ],
  setupSteps: [
    "Register an application in Microsoft Entra ID and record the Application (client) ID.",
    "Add https://<agent-bom-host>/v1/auth/oidc/callback under Authentication → Web redirect URIs.",
    "Under Certificates & secrets, create a client secret and paste it into the secret field.",
    "Define app roles (admin/analyst/viewer) so the roles claim drives agent-bom RBAC.",
  ],
};

const GOOGLE_OIDC: SsoProviderPreset = {
  id: "google-oidc",
  label: "Google Workspace",
  protocol: "oidc",
  tagline: "Google Workspace via accounts.google.com OpenID Connect.",
  generic: false,
  docsHint: "Google Cloud console → APIs & Services → Credentials → OAuth client ID.",
  fields: [
    {
      key: "issuer",
      envVar: "AGENT_BOM_OIDC_ISSUER",
      label: "Issuer",
      kind: "config",
      value: "https://accounts.google.com",
      placeholder: "https://accounts.google.com",
      hint: "Fixed issuer for all Google Workspace tenants.",
    },
    {
      key: "jwks_uri",
      envVar: "AGENT_BOM_OIDC_JWKS_URI",
      label: "JWKS URI",
      kind: "config",
      value: "https://www.googleapis.com/oauth2/v3/certs",
      placeholder: "https://www.googleapis.com/oauth2/v3/certs",
    },
    {
      key: "scopes",
      envVar: "AGENT_BOM_OIDC_SCOPES",
      label: "Scopes",
      kind: "config",
      value: "openid profile email",
      placeholder: "openid profile email",
    },
    {
      key: "role_claim",
      envVar: "AGENT_BOM_OIDC_ROLE_CLAIM",
      label: "Role claim",
      kind: "config",
      value: "groups",
      placeholder: "groups",
      hint: "Google does not emit groups by default — add them via a mapping / directory sync.",
    },
    {
      key: "tenant_claim",
      envVar: "AGENT_BOM_OIDC_TENANT_CLAIM",
      label: "Tenant claim",
      kind: "config",
      value: "hd",
      placeholder: "hd",
      hint: "The hd (hosted domain) claim identifies the Workspace domain.",
    },
    ...oidcTenantClientFields("1234567890-abc123.apps.googleusercontent.com", "1234567890-abc123.apps.googleusercontent.com"),
  ],
  setupSteps: [
    "In Google Cloud console, create an OAuth 2.0 Web application client id + secret.",
    "Add https://<agent-bom-host>/v1/auth/oidc/callback as an authorized redirect URI.",
    "Restrict sign-in to your Workspace domain and verify the hd claim.",
    "Map Workspace groups to agent-bom roles (admin/analyst/viewer).",
  ],
};

const GENERIC_OIDC: SsoProviderPreset = {
  id: "generic-oidc",
  label: "Generic OIDC",
  protocol: "oidc",
  tagline: "Any standards-compliant OIDC issuer — fill in every field manually.",
  generic: true,
  docsHint: "Provide the issuer's /.well-known/openid-configuration values.",
  fields: [
    {
      key: "issuer",
      envVar: "AGENT_BOM_OIDC_ISSUER",
      label: "Issuer",
      kind: "config",
      value: "",
      placeholder: "https://idp.your-org.example",
      hint: "Discovery is fetched from <issuer>/.well-known/openid-configuration.",
    },
    {
      key: "jwks_uri",
      envVar: "AGENT_BOM_OIDC_JWKS_URI",
      label: "JWKS URI",
      kind: "config",
      value: "",
      placeholder: "https://idp.your-org.example/.well-known/jwks.json",
    },
    {
      key: "scopes",
      envVar: "AGENT_BOM_OIDC_SCOPES",
      label: "Scopes",
      kind: "config",
      value: "",
      placeholder: "openid profile email",
    },
    {
      key: "role_claim",
      envVar: "AGENT_BOM_OIDC_ROLE_CLAIM",
      label: "Role claim",
      kind: "config",
      value: "",
      placeholder: "agent_bom_role",
    },
    {
      key: "tenant_claim",
      envVar: "AGENT_BOM_OIDC_TENANT_CLAIM",
      label: "Tenant claim",
      kind: "config",
      value: "",
      placeholder: "tenant_id",
    },
    {
      key: "audience",
      envVar: "AGENT_BOM_OIDC_AUDIENCE",
      label: "Audience (aud)",
      kind: "tenant",
      value: "",
      placeholder: "agent-bom",
    },
    {
      key: "client_id",
      envVar: "AGENT_BOM_OIDC_CLIENT_ID",
      label: "Client ID",
      kind: "tenant",
      value: "",
      placeholder: "your-client-id",
    },
    {
      key: "redirect_uri",
      envVar: "AGENT_BOM_OIDC_REDIRECT_URI",
      label: "Redirect URI",
      kind: "tenant",
      value: "",
      placeholder: "https://agent-bom.your-org.example/v1/auth/oidc/callback",
    },
    {
      key: "client_secret",
      envVar: "AGENT_BOM_OIDC_CLIENT_SECRET",
      label: "Client secret",
      kind: "secret",
      value: "",
      placeholder: "Paste after creating the app — encrypted at rest, never prefilled",
    },
  ],
  setupSteps: [
    "Read the issuer's discovery document at /.well-known/openid-configuration.",
    "Register agent-bom as a confidential client and add the callback redirect URI.",
    "Map an audience and a role claim, then supply the client id + secret.",
  ],
};

// ── SAML presets ────────────────────────────────────────────────────────────

const OKTA_SAML: SsoProviderPreset = {
  id: "okta-saml",
  label: "Okta",
  protocol: "saml",
  tagline: "Okta SAML 2.0 app integration.",
  generic: false,
  docsHint: "Okta admin → Applications → Create App Integration → SAML 2.0.",
  fields: [
    {
      key: "idp_entity_id",
      envVar: "AGENT_BOM_SAML_IDP_ENTITY_ID",
      label: "IdP entity ID (issuer)",
      kind: "config",
      value: "http://www.okta.com/{appId}",
      placeholder: "http://www.okta.com/exk1a2b3c4D5E6F7g8",
      hint: "Shown on the Okta app's Sign On tab as the Identity Provider Issuer.",
    },
    {
      key: "idp_sso_url",
      envVar: "AGENT_BOM_SAML_IDP_SSO_URL",
      label: "IdP SSO URL",
      kind: "config",
      value: "https://{yourOktaDomain}/app/{appName}/{appId}/sso/saml",
      placeholder: "https://your-org.okta.com/app/agent-bom/exk.../sso/saml",
    },
    samlIdpCertField(),
    ...samlAttributeFields(),
    ...samlServiceProviderFields(),
  ],
  setupSteps: [
    "Create an Okta SAML 2.0 app and set the SSO URL / ACS to the SP ACS URL above.",
    "Set the Audience URI to the SP entity ID above.",
    "Add attribute statements named agent_bom_role and tenant_id.",
    "Download the IdP signing certificate from the Sign On tab and paste it in.",
  ],
};

const ENTRA_SAML: SsoProviderPreset = {
  id: "entra-saml",
  label: "Microsoft Entra ID",
  protocol: "saml",
  tagline: "Entra ID (Azure AD) SAML 2.0 enterprise application.",
  generic: false,
  docsHint: "Entra admin center → Enterprise applications → New → single sign-on (SAML).",
  fields: [
    {
      key: "idp_entity_id",
      envVar: "AGENT_BOM_SAML_IDP_ENTITY_ID",
      label: "IdP entity ID (issuer)",
      kind: "config",
      value: "https://sts.windows.net/{tenantId}/",
      placeholder: "https://sts.windows.net/00000000-0000-0000-0000-000000000000/",
      hint: "The Microsoft Entra Identifier from the SAML SSO blade.",
    },
    {
      key: "idp_sso_url",
      envVar: "AGENT_BOM_SAML_IDP_SSO_URL",
      label: "IdP SSO URL",
      kind: "config",
      value: "https://login.microsoftonline.com/{tenantId}/saml2",
      placeholder: "https://login.microsoftonline.com/<tenant-id>/saml2",
    },
    samlIdpCertField(),
    ...samlAttributeFields(),
    ...samlServiceProviderFields(),
  ],
  setupSteps: [
    "Create an Entra enterprise application and choose SAML single sign-on.",
    "Set the Identifier (Entity ID) to the SP entity ID and Reply URL to the SP ACS URL above.",
    "Add claims for agent_bom_role and tenant_id.",
    "Download the Certificate (Base64) and paste it into the IdP certificate field.",
  ],
};

const GOOGLE_SAML: SsoProviderPreset = {
  id: "google-saml",
  label: "Google Workspace",
  protocol: "saml",
  tagline: "Google Workspace custom SAML app.",
  generic: false,
  docsHint: "Google Admin console → Apps → Web and mobile apps → Add custom SAML app.",
  fields: [
    {
      key: "idp_entity_id",
      envVar: "AGENT_BOM_SAML_IDP_ENTITY_ID",
      label: "IdP entity ID (issuer)",
      kind: "config",
      value: "https://accounts.google.com/o/saml2?idpid={idpId}",
      placeholder: "https://accounts.google.com/o/saml2?idpid=C01abc234",
      hint: "The Entity ID from the Google SAML app's IdP metadata.",
    },
    {
      key: "idp_sso_url",
      envVar: "AGENT_BOM_SAML_IDP_SSO_URL",
      label: "IdP SSO URL",
      kind: "config",
      value: "https://accounts.google.com/o/saml2/idp?idpid={idpId}",
      placeholder: "https://accounts.google.com/o/saml2/idp?idpid=C01abc234",
    },
    samlIdpCertField(),
    ...samlAttributeFields(),
    ...samlServiceProviderFields(),
  ],
  setupSteps: [
    "In the Google Admin console, add a custom SAML app for agent-bom.",
    "Set the ACS URL to the SP ACS URL and Entity ID to the SP entity ID above.",
    "Add attribute mappings for agent_bom_role and tenant_id.",
    "Download the IdP certificate from the Google metadata and paste it in.",
  ],
};

const GENERIC_SAML: SsoProviderPreset = {
  id: "generic-saml",
  label: "Generic SAML",
  protocol: "saml",
  tagline: "Any SAML 2.0 IdP — fill in every field manually.",
  generic: true,
  docsHint: "Provide the IdP's entity ID, SSO URL and signing certificate.",
  fields: [
    {
      key: "idp_entity_id",
      envVar: "AGENT_BOM_SAML_IDP_ENTITY_ID",
      label: "IdP entity ID (issuer)",
      kind: "config",
      value: "",
      placeholder: "https://idp.your-org.example/metadata",
    },
    {
      key: "idp_sso_url",
      envVar: "AGENT_BOM_SAML_IDP_SSO_URL",
      label: "IdP SSO URL",
      kind: "config",
      value: "",
      placeholder: "https://idp.your-org.example/sso",
    },
    {
      key: "idp_x509_cert",
      envVar: "AGENT_BOM_SAML_IDP_X509_CERT",
      label: "IdP signing certificate (X.509)",
      kind: "tenant",
      value: "",
      placeholder: "-----BEGIN CERTIFICATE-----\n…",
    },
    {
      key: "role_attribute",
      envVar: "AGENT_BOM_SAML_ROLE_ATTRIBUTE",
      label: "Role attribute",
      kind: "config",
      value: "",
      placeholder: "agent_bom_role",
    },
    {
      key: "tenant_attribute",
      envVar: "AGENT_BOM_SAML_TENANT_ATTRIBUTE",
      label: "Tenant attribute",
      kind: "config",
      value: "",
      placeholder: "tenant_id",
    },
    {
      key: "sp_entity_id",
      envVar: "AGENT_BOM_SAML_SP_ENTITY_ID",
      label: "SP entity ID",
      kind: "config",
      value: "",
      placeholder: "https://agent-bom.your-org.example/v1/auth/saml/metadata",
    },
    {
      key: "sp_acs_url",
      envVar: "AGENT_BOM_SAML_SP_ACS_URL",
      label: "SP ACS URL",
      kind: "config",
      value: "",
      placeholder: "https://agent-bom.your-org.example/v1/auth/saml/login",
    },
  ],
  setupSteps: [
    "Register agent-bom as a SAML SP using the SP entity ID + ACS URL.",
    "Copy the IdP entity ID, SSO URL and signing certificate from the IdP.",
    "Map role and tenant attributes onto agent_bom_role / tenant_id.",
  ],
};

// ── Catalog + lookups ───────────────────────────────────────────────────────

export const SSO_OIDC_PRESETS: SsoProviderPreset[] = [OKTA_OIDC, ENTRA_OIDC, GOOGLE_OIDC, GENERIC_OIDC];
export const SSO_SAML_PRESETS: SsoProviderPreset[] = [OKTA_SAML, ENTRA_SAML, GOOGLE_SAML, GENERIC_SAML];

export const SSO_PROVIDER_PRESETS: Record<SsoProviderId, SsoProviderPreset> = {
  "okta-oidc": OKTA_OIDC,
  "entra-oidc": ENTRA_OIDC,
  "google-oidc": GOOGLE_OIDC,
  "generic-oidc": GENERIC_OIDC,
  "okta-saml": OKTA_SAML,
  "entra-saml": ENTRA_SAML,
  "google-saml": GOOGLE_SAML,
  "generic-saml": GENERIC_SAML,
};

export function ssoProviderPreset(id: string): SsoProviderPreset | null {
  if (id in SSO_PROVIDER_PRESETS) {
    return SSO_PROVIDER_PRESETS[id as SsoProviderId];
  }
  return null;
}

export function ssoPresetsForProtocol(protocol: SsoProtocol): SsoProviderPreset[] {
  return protocol === "oidc" ? SSO_OIDC_PRESETS : SSO_SAML_PRESETS;
}

/**
 * Apply a preset to produce the initial form values keyed by field key.
 * Config fields carry their pre-filled template; `tenant`/`secret` fields and
 * every generic field stay blank so the operator supplies them. Secrets are
 * never populated.
 */
export function applySsoPreset(preset: SsoProviderPreset): Record<string, string> {
  const values: Record<string, string> = {};
  for (const field of preset.fields) {
    values[field.key] = field.kind === "secret" ? "" : field.value;
  }
  return values;
}

/** Placeholder emitted for any field the operator must supply. */
function envPlaceholder(field: SsoPresetField): string {
  const token = field.key.toUpperCase();
  return `<${token}>`;
}

/**
 * Build a copy-pasteable env-var block for a preset, mirroring the cloud
 * wizard's grant-script builder. Config fields render their template value;
 * `tenant`/`secret` fields render a `<PLACEHOLDER>` — a real secret is never
 * emitted.
 */
export function buildSsoEnvSnippet(preset: SsoProviderPreset): string {
  const header = `# agent-bom ${preset.label} ${preset.protocol.toUpperCase()} SSO — replace {placeholders} with your values`;
  const lines = preset.fields.map((field) => {
    const rendered = field.kind === "config" && field.value ? field.value : envPlaceholder(field);
    return `${field.envVar}=${rendered}`;
  });
  return [header, ...lines].join("\n");
}
