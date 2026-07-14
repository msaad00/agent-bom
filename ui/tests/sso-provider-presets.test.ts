import { describe, expect, it } from "vitest";

import {
  SSO_OIDC_PRESETS,
  SSO_PROVIDER_PRESETS,
  SSO_SAML_PRESETS,
  applySsoPreset,
  buildSsoEnvSnippet,
  ssoPresetsForProtocol,
  ssoProviderPreset,
  type SsoProviderPreset,
} from "@/lib/sso-provider-presets";

const ALL_PRESETS: SsoProviderPreset[] = Object.values(SSO_PROVIDER_PRESETS);

describe("sso provider preset catalog", () => {
  it("ships Okta, Entra, Google and Generic for both OIDC and SAML", () => {
    expect(ssoPresetsForProtocol("oidc").map((p) => p.id)).toEqual([
      "okta-oidc",
      "entra-oidc",
      "google-oidc",
      "generic-oidc",
    ]);
    expect(ssoPresetsForProtocol("saml").map((p) => p.id)).toEqual([
      "okta-saml",
      "entra-saml",
      "google-saml",
      "generic-saml",
    ]);
    // The exported arrays are the same objects the lookup resolves.
    expect(SSO_OIDC_PRESETS).toBe(ssoPresetsForProtocol("oidc"));
    expect(SSO_SAML_PRESETS).toBe(ssoPresetsForProtocol("saml"));
  });

  it("resolves presets by id and returns null for unknown ids", () => {
    expect(ssoProviderPreset("okta-oidc")?.label).toBe("Okta");
    expect(ssoProviderPreset("nope")).toBeNull();
  });

  it("maps every prefilled field to a real AGENT_BOM_* env var", () => {
    for (const preset of ALL_PRESETS) {
      expect(preset.fields.length).toBeGreaterThan(0);
      for (const field of preset.fields) {
        expect(field.envVar.startsWith("AGENT_BOM_")).toBe(true);
        expect(field.key).toBeTruthy();
        expect(field.label).toBeTruthy();
      }
    }
  });
});

describe("selecting an OIDC provider preset fills the issuer template", () => {
  it("Okta prefills the /oauth2/default issuer + JWKS with a domain placeholder", () => {
    const filled = applySsoPreset(ssoProviderPreset("okta-oidc")!);
    expect(filled.issuer).toBe("https://{yourOktaDomain}/oauth2/default");
    expect(filled.issuer?.startsWith("https://")).toBe(true);
    expect(filled.issuer).toContain("{yourOktaDomain}");
    expect(filled.jwks_uri).toBe("https://{yourOktaDomain}/oauth2/default/v1/keys");
  });

  it("Entra prefills the tenant-scoped v2.0 authority + keys endpoint", () => {
    const filled = applySsoPreset(ssoProviderPreset("entra-oidc")!);
    expect(filled.issuer).toBe("https://login.microsoftonline.com/{tenantId}/v2.0");
    expect(filled.issuer).toContain("{tenantId}");
    expect(filled.jwks_uri).toBe("https://login.microsoftonline.com/{tenantId}/discovery/v2.0/keys");
  });

  it("Google prefills the fixed accounts.google.com issuer + certs endpoint", () => {
    const filled = applySsoPreset(ssoProviderPreset("google-oidc")!);
    expect(filled.issuer).toBe("https://accounts.google.com");
    expect(filled.jwks_uri).toBe("https://www.googleapis.com/oauth2/v3/certs");
  });
});

describe("selecting a SAML provider preset fills the IdP endpoints", () => {
  it("Okta prefills the IdP entity id + SSO url templates", () => {
    const filled = applySsoPreset(ssoProviderPreset("okta-saml")!);
    expect(filled.idp_entity_id).toContain("okta.com");
    expect(filled.idp_sso_url).toContain("{yourOktaDomain}");
  });

  it("Entra prefills the tenant-scoped saml2 endpoints", () => {
    const filled = applySsoPreset(ssoProviderPreset("entra-saml")!);
    expect(filled.idp_sso_url).toBe("https://login.microsoftonline.com/{tenantId}/saml2");
    expect(filled.idp_entity_id).toContain("{tenantId}");
  });
});

describe("Generic stays fully manual", () => {
  it("leaves every generic field blank so the operator supplies all values", () => {
    for (const id of ["generic-oidc", "generic-saml"] as const) {
      const preset = ssoProviderPreset(id)!;
      expect(preset.generic).toBe(true);
      const filled = applySsoPreset(preset);
      for (const value of Object.values(filled)) {
        expect(value).toBe("");
      }
    }
  });
});

describe("secrets are never prefilled or emitted", () => {
  it("no secret-kind field on any preset carries a value", () => {
    for (const preset of ALL_PRESETS) {
      for (const field of preset.fields) {
        if (field.kind === "secret") {
          expect(field.value).toBe("");
        }
      }
    }
  });

  it("only OIDC presets carry a client-secret field and it is always empty", () => {
    const oktaSecret = ssoProviderPreset("okta-oidc")!.fields.find((f) => f.key === "client_secret");
    expect(oktaSecret?.kind).toBe("secret");
    expect(oktaSecret?.value).toBe("");
    // applied form never contains a non-empty client secret.
    expect(applySsoPreset(ssoProviderPreset("okta-oidc")!).client_secret).toBe("");
    // SAML has no secret (the IdP cert is a public signing certificate).
    expect(ssoProviderPreset("okta-saml")!.fields.some((f) => f.kind === "secret")).toBe(false);
  });

  it("the generated env snippet placeholders a secret, never a real value", () => {
    const snippet = buildSsoEnvSnippet(ssoProviderPreset("entra-oidc")!);
    expect(snippet).toContain("AGENT_BOM_OIDC_ISSUER=");
    expect(snippet).toContain("https://login.microsoftonline.com/{tenantId}/v2.0");
    // client secret line exists but only as a paste-me placeholder in angle brackets.
    const secretLine = snippet.split("\n").find((line) => line.startsWith("AGENT_BOM_OIDC_CLIENT_SECRET="));
    expect(secretLine).toBeDefined();
    expect(secretLine).toMatch(/=<.*>$/);
  });
});
