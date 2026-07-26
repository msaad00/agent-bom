/**
 * User-facing text for an unhandled render error.
 *
 * An exception message is developer output. It routinely carries a stack
 * fragment, an internal path, a connection string, or a raw upstream response
 * body — a demo capture once showed `Invalid time value` as the entire page.
 * None of that helps the reader and some of it should never leave the server.
 *
 * So the boundary and its telemetry report both use a fixed string chosen from
 * the error's shape. The server-generated digest remains the correlation key;
 * caller-controlled exception text never crosses the browser/API boundary.
 */

export const GENERIC_ERROR_MESSAGE =
  "This page could not be displayed. The error has been reported. Try again, and if it keeps happening, check the control-plane logs.";

export const NETWORK_ERROR_MESSAGE =
  "The dashboard could not reach the control plane. Check that it is running and reachable, then try again.";

export const PERMISSION_ERROR_MESSAGE =
  "You do not have access to this view. Ask an administrator to check your role, then try again.";

export const NOT_FOUND_ERROR_MESSAGE = "That item no longer exists. It may have been deleted or moved.";

const NETWORK_HINTS = ["failed to fetch", "networkerror", "load failed", "err_connection", "econnrefused"];
const PERMISSION_HINTS = ["401", "403", "unauthorized", "forbidden"];
const NOT_FOUND_HINTS = ["404", "not found"];

/**
 * Map an error to a fixed, safe message. Never returns caller-controlled text.
 */
export function errorBoundaryMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  const probe = raw.toLowerCase();

  if (NETWORK_HINTS.some((hint) => probe.includes(hint))) return NETWORK_ERROR_MESSAGE;
  if (PERMISSION_HINTS.some((hint) => probe.includes(hint))) return PERMISSION_ERROR_MESSAGE;
  if (NOT_FOUND_HINTS.some((hint) => probe.includes(hint))) return NOT_FOUND_ERROR_MESSAGE;
  return GENERIC_ERROR_MESSAGE;
}

/**
 * Short, non-secret correlation handle so a user can quote something useful.
 *
 * Next.js digests are server-generated hashes, not error text, so they are safe
 * to display and are what an operator greps for.
 */
export function errorReference(digest?: string): string | null {
  const trimmed = (digest ?? "").trim();
  // Next.js digests are hash-like values. Fail closed if a caller supplies
  // punctuation, whitespace, or another shape that could be raw error text.
  return /^[a-f0-9]{8,64}$/i.test(trimmed) ? trimmed.slice(0, 12) : null;
}
