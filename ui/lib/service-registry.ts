import type { ServiceEntry, ServiceId, ServiceState } from "@/lib/api-types";

export const SERVICE_META: Record<
  ServiceId,
  { label: string; unlockHref: string; unlockLabel: string }
> = {
  cloud_accounts: {
    label: "Cloud accounts",
    unlockHref: "/connections",
    unlockLabel: "Connect cloud account",
  },
  data_sources: {
    label: "Data sources",
    unlockHref: "/connections?tab=sources",
    unlockLabel: "Add data source",
  },
  local_agents: {
    label: "Local agents",
    unlockHref: "/manifest",
    unlockLabel: "Open AI BOM",
  },
  fleet: {
    label: "Fleet",
    unlockHref: "/fleet",
    unlockLabel: "Sync fleet",
  },
  runtime_proxy: {
    label: "Runtime proxy",
    unlockHref: "/runtime?tab=proxy",
    unlockLabel: "Enable proxy",
  },
  runtime_gateway: {
    label: "Runtime gateway",
    unlockHref: "/runtime?tab=gateway",
    unlockLabel: "Enable gateway",
  },
  runtime_traces: {
    label: "Runtime traces",
    unlockHref: "/traces",
    unlockLabel: "Enable traces",
  },
  ai_spend: {
    label: "AI spend",
    unlockHref: "/runtime?tab=proxy",
    unlockLabel: "Set up runtime usage",
  },
  compliance: {
    label: "Compliance",
    unlockHref: "/scan",
    unlockLabel: "Run scan",
  },
};

const STATE_LABEL: Record<ServiceState, string> = {
  locked: "Locked",
  connected: "Connected",
  live: "Live",
};

export function serviceEntry(
  registry: Partial<Record<ServiceId, ServiceEntry>> | undefined,
  id: ServiceId,
): ServiceEntry {
  return registry?.[id] ?? { state: "locked", count: 0 };
}

export function serviceStateLabel(state: ServiceState): string {
  return STATE_LABEL[state];
}

export function serviceRequiresLabel(
  registry: Partial<Record<ServiceId, ServiceEntry>> | undefined,
  id: ServiceId,
): string | null {
  const entry = serviceEntry(registry, id);
  if (!entry.requires?.length) {
    return null;
  }
  return entry.requires
    .map((required) => SERVICE_META[required as ServiceId]?.label ?? required)
    .join(", ");
}

/** Route usage setup to an existing runtime surface, then its declared dependency. */
export function serviceSetupAction(
  id: ServiceId,
  entry: ServiceEntry,
  registry?: Partial<Record<ServiceId, ServiceEntry>>,
): { href: string; label: string } {
  const meta = SERVICE_META[id];
  if (id !== "ai_spend") return { href: meta.unlockHref, label: meta.unlockLabel };
  const runtimeDependencies = (entry.requires ?? []).filter(
    (dependency): dependency is "runtime_proxy" | "runtime_gateway" =>
      dependency === "runtime_proxy" || dependency === "runtime_gateway",
  );
  const candidates = [...new Set([...runtimeDependencies, "runtime_proxy", "runtime_gateway"] as const)];
  const target = candidates.find((candidate) => {
    const state = registry?.[candidate]?.state;
    return state === "connected" || state === "live";
  }) ?? candidates[0]!;
  return { href: SERVICE_META[target].unlockHref, label: meta.unlockLabel };
}
