/** Overview is the shared posture landing; explicit task deep links still win. */
export const OVERVIEW_LANDING = "/";

export function defaultOperatorLanding(returnTo: string | null | undefined): string {
  const raw = (returnTo ?? "").trim();
  if (!raw || raw === "/") return OVERVIEW_LANDING;
  return raw;
}
