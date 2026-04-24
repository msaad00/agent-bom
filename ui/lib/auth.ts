const SESSION_API_KEY = "agent-bom-ui-api-key";
const CSRF_COOKIE = "agent_bom_csrf";

function hasWindow(): boolean {
  return typeof window !== "undefined";
}

export function getSessionApiKey(): string {
  if (!hasWindow()) return "";
  try {
    return window.sessionStorage.getItem(SESSION_API_KEY)?.trim() ?? "";
  } catch {
    return "";
  }
}

export function setSessionApiKey(rawKey: string): void {
  if (!hasWindow()) return;
  const value = rawKey.trim();
  try {
    if (!value) {
      window.sessionStorage.removeItem(SESSION_API_KEY);
      return;
    }
    window.sessionStorage.setItem(SESSION_API_KEY, value);
  } catch {
    // Ignore storage failures; the user can still retry within the current render.
  }
}

export function clearSessionApiKey(): void {
  if (!hasWindow()) return;
  try {
    window.sessionStorage.removeItem(SESSION_API_KEY);
  } catch {
    // Ignore storage failures; best-effort cleanup only.
  }
}

export function getSessionAuthHeaders(): Record<string, string> {
  const apiKey = getSessionApiKey();
  const csrf = getBrowserCsrfToken();
  return {
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    ...(csrf ? { "X-Agent-Bom-CSRF": csrf } : {}),
  };
}

export function getSessionWebSocketToken(): string {
  return getSessionApiKey();
}

export function getBrowserCsrfToken(): string {
  if (!hasWindow()) return "";
  try {
    const prefix = `${CSRF_COOKIE}=`;
    const cookie = document.cookie
      .split(";")
      .map((part) => part.trim())
      .find((part) => part.startsWith(prefix));
    return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : "";
  } catch {
    return "";
  }
}
