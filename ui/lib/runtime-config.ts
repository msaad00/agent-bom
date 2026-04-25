declare global {
  interface Window {
    __AGENT_BOM_CONFIG__?: {
      apiUrl?: string;
      allowSessionStorageApiKey?: boolean;
    };
  }
}

const DEFAULT_API_URL = "http://localhost:8422";

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

export function allowSessionStorageApiKeyFallback(): boolean {
  if (typeof window !== "undefined" && typeof window.__AGENT_BOM_CONFIG__?.allowSessionStorageApiKey === "boolean") {
    return window.__AGENT_BOM_CONFIG__.allowSessionStorageApiKey;
  }
  return process.env.NEXT_PUBLIC_ALLOW_SESSION_STORAGE_API_KEY === "1";
}
