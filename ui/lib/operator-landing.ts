/**
 * Default post-login / home landing for SecOps investigation-first IA.
 * Overview remains available in nav; anonymous demos and explicit returnTo
 * still win via safeReturnPath.
 */
export const SECOPS_DEFAULT_LANDING = "/security-graph";

export function defaultOperatorLanding(returnTo: string | null | undefined): string {
  const raw = (returnTo ?? "").trim();
  if (!raw || raw === "/") return SECOPS_DEFAULT_LANDING;
  return raw;
}
