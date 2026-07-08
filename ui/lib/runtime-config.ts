declare global {
  interface Window {
    __AGENT_BOM_CONFIG__?: {
      apiUrl?: string | undefined;
      signInUrl?: string | undefined;
    } | undefined;
  }
}

const DEFAULT_API_URL = "http://localhost:8422";
const DEFAULT_SIGN_IN_URL = "/login";

function normalizeApiUrl(value: string | undefined | null): string | undefined {
  if (value == null) {
    return undefined;
  }
  return value.trim();
}

function sameOriginRuntimeApiUrl(value: string | undefined): string | undefined {
  if (value === undefined || typeof window === "undefined") {
    return value;
  }
  if (value === "") {
    return "";
  }
  try {
    const parsed = new URL(value, window.location.origin);
    if (parsed.origin !== window.location.origin) {
      return "";
    }
    return parsed.origin === window.location.origin ? parsed.pathname.replace(/\/$/, "") : "";
  } catch {
    return "";
  }
}

export function getConfiguredApiUrl(): string {
  if (typeof window !== "undefined") {
    const runtimeValue = sameOriginRuntimeApiUrl(normalizeApiUrl(window.__AGENT_BOM_CONFIG__?.apiUrl));
    if (runtimeValue !== undefined) {
      return runtimeValue;
    }
    const envValue = sameOriginRuntimeApiUrl(normalizeApiUrl(process.env.NEXT_PUBLIC_API_URL));
    if (envValue !== undefined) {
      return envValue;
    }
    return "";
  }
  return normalizeApiUrl(process.env.NEXT_PUBLIC_API_URL) ?? "";
}

export function getDisplayApiUrl(): string {
  return getConfiguredApiUrl() || DEFAULT_API_URL;
}

/**
 * Target for the demo-mode "connect your cloud" CTA. Points at the sign-in /
 * get-started flow of the authenticated product. Configurable at runtime via
 * ``window.__AGENT_BOM_CONFIG__.signInUrl`` (for hosted deployments that funnel
 * to an external product URL) or the ``NEXT_PUBLIC_SIGN_IN_URL`` build env,
 * defaulting to the in-app ``/login`` route.
 */
export function getSignInUrl(): string {
  if (typeof window !== "undefined") {
    const runtimeValue = normalizeApiUrl(window.__AGENT_BOM_CONFIG__?.signInUrl);
    if (runtimeValue) {
      return runtimeValue;
    }
  }
  const envValue = normalizeApiUrl(process.env.NEXT_PUBLIC_SIGN_IN_URL);
  if (envValue) {
    return envValue;
  }
  return DEFAULT_SIGN_IN_URL;
}
