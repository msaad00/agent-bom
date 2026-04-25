const CSRF_COOKIE = "agent_bom_csrf";

function hasWindow(): boolean {
  return typeof window !== "undefined";
}

export function getSessionApiKey(): string {
  return "";
}

export function setSessionApiKey(rawKey: string): void {
  void rawKey;
}

export function clearSessionApiKey(): void {
  return;
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
  return "";
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
