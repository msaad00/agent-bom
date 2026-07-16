/**
 * Sign-in presets for the /login SSO button.
 *
 * The control plane runs a single configured browser-OIDC issuer and exposes
 * its detected provider brand as `sso_provider` on `/v1/auth/me` (see
 * `configured_browser_sso_provider` in src/agent_bom/api/oidc_browser.py). This
 * is presentation only — it brands the existing `/v1/auth/oidc/login` button
 * ("Sign in with Okta") instead of a generic label. It never forks the auth
 * flow, and an unrecognized issuer honestly falls back to the generic label.
 */

export type SsoLoginProviderId = "okta" | "entra" | "google";

export interface SsoLoginPreset {
  /** Provider brand, or "generic" when the issuer is unrecognized/absent. */
  id: SsoLoginProviderId | "generic";
  /** Short brand name used in the sign-in copy (e.g. "Okta"). */
  label: string;
  /** Button/link text (e.g. "Sign in with Okta"). */
  buttonLabel: string;
}

const BRANDED: Record<SsoLoginProviderId, { label: string; buttonLabel: string }> = {
  okta: { label: "Okta", buttonLabel: "Sign in with Okta" },
  entra: { label: "Microsoft", buttonLabel: "Sign in with Microsoft" },
  google: { label: "Google", buttonLabel: "Sign in with Google" },
};

const GENERIC: SsoLoginPreset = {
  id: "generic",
  label: "SSO",
  buttonLabel: "Sign in with SSO",
};

function isBrandedProviderId(value: string): value is SsoLoginProviderId {
  return value in BRANDED;
}

/**
 * Resolve the sign-in preset for a provider id from `/v1/auth/me`.
 * A null/undefined/unknown provider yields the generic "Sign in with SSO"
 * preset so the button never claims a vendor it can't drive.
 */
export function ssoLoginPreset(provider: string | null | undefined): SsoLoginPreset {
  if (typeof provider === "string" && isBrandedProviderId(provider)) {
    return { id: provider, ...BRANDED[provider] };
  }
  return GENERIC;
}
