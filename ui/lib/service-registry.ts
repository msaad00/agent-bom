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
    unlockHref: "/sources",
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
    unlockHref: "/runtime",
    unlockLabel: "Enable proxy",
  },
  runtime_gateway: {
    label: "Runtime gateway",
    unlockHref: "/runtime",
    unlockLabel: "Enable gateway",
  },
  runtime_traces: {
    label: "Runtime traces",
    unlockHref: "/traces",
    unlockLabel: "Enable traces",
  },
  ai_spend: {
    label: "AI spend",
    unlockHref: "/cost",
    unlockLabel: "View AI spend",
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
