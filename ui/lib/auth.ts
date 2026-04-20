const SESSION_API_KEY = "agent-bom-ui-api-key";

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
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
}

export function getSessionWebSocketToken(): string {
  return getSessionApiKey();
}
