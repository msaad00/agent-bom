/** Sanitize post-login redirects — block open redirects and protocol-relative paths. */

const BLOCKED_PREFIXES = ["/login"];

export function safeReturnPath(value: string | null): string {
  if (!value) return "/";

  const candidate = value.trim();
  if (!candidate) return "/";

  // Reject backslashes and control chars (encoded open-redirect tricks).
  if (/[\\<>]/.test(candidate) || /[\u0000-\u001f\u007f]/.test(candidate)) {
    return "/";
  }

  // Must be a same-origin relative path.
  if (!candidate.startsWith("/") || candidate.startsWith("//")) {
    return "/";
  }

  for (const blocked of BLOCKED_PREFIXES) {
    if (candidate === blocked || candidate.startsWith(`${blocked}/`) || candidate.startsWith(`${blocked}?`)) {
      return "/";
    }
  }

  return candidate;
}
