/** Preserve canonical IDs exactly; URLSearchParams has already decoded them. */
export function requestedGraphRoot(params: { get(name: string): string | null } | null): string {
  return params?.get("root") ?? params?.get("node") ?? params?.get("agent") ?? "";
}
