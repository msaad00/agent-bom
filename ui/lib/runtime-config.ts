declare global {
  interface Window {
    __AGENT_BOM_CONFIG__?: {
      apiUrl?: string;
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

export function getConfiguredApiUrl(): string {
  if (typeof window !== "undefined") {
    const runtimeValue = normalizeApiUrl(window.__AGENT_BOM_CONFIG__?.apiUrl);
    if (runtimeValue !== undefined) {
      return runtimeValue;
    }
  }
  return normalizeApiUrl(process.env.NEXT_PUBLIC_API_URL) ?? "";
}

export function getDisplayApiUrl(): string {
  return getConfiguredApiUrl() || DEFAULT_API_URL;
}
