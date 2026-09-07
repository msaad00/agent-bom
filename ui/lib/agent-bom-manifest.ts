import type { AgentBomManifestResponse } from "./api";

export type ManifestReviewFilter = "all" | "review needed" | "not assessed";
export type ManifestFreshnessFilter = "all" | "seen_24h" | "seen_7d" | "stale" | "unknown";
export type ManifestRuntimeFilter = "all" | "gateway bound" | "runtime observed" | "shadow runtime" | "inventory only";

export interface ManifestFilters {
  query: string;
  source: string;
  owner: string;
  review: ManifestReviewFilter;
  freshness: ManifestFreshnessFilter;
  runtime: ManifestRuntimeFilter;
}

export interface ManifestRow {
  id: string;
  agentName: string;
  owner: string;
  environment: string;
  name: string;
  transport: string;
  authMode: string;
  source: string;
  toolCount: number | null;
  credentialRefs: string[];
  runtimeState: ManifestRuntimeFilter;
  freshness: Exclude<ManifestFreshnessFilter, "all">;
  reviewStatus: ManifestReviewFilter;
  lastSeen: string;
  warnings: string[];
  reviewIndicators: string[];
}


export const DEFAULT_MANIFEST_FILTERS: ManifestFilters = {
  query: "",
  source: "all",
  owner: "all",
  review: "all",
  freshness: "all",
  runtime: "all",
};

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item)).filter(Boolean);
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function credentialNames(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((ref) => (typeof ref === "object" && ref ? asString((ref as Record<string, unknown>).name) : ""))
    .filter(Boolean);
}

function rowSource(serverRow: Record<string, unknown>, observed: Record<string, unknown>, manifest: AgentBomManifestResponse): string {
  const discovery = asRecord(serverRow.discovery);
  const discoverySources = asStringList(discovery.sources);
  if (discoverySources.length > 0) return discoverySources.join(", ");
  const observedVia = asStringList(observed.via);
  if (observedVia.length > 0) return observedVia.join(", ");
  return asString(manifest.source, "unknown");
}

export function classifyFreshness(lastSeen: string, now: Date = new Date()): ManifestRow["freshness"] {
  if (!lastSeen || lastSeen === "-") return "unknown";
  const parsed = Date.parse(lastSeen);
  if (!Number.isFinite(parsed)) return "unknown";
  const ageMs = Math.max(0, now.getTime() - parsed);
  const dayMs = 24 * 60 * 60 * 1000;
  if (ageMs <= dayMs) return "seen_24h";
  if (ageMs <= 7 * dayMs) return "seen_7d";
  return "stale";
}

function classifyRuntimeState(observed: Record<string, unknown>): ManifestRow["runtimeState"] {
  const runtimeObserved = Boolean(observed.runtime_observed);
  const gatewayRegistered = Boolean(observed.gateway_registered);
  const configuredLocally = Boolean(observed.configured_locally);
  const fleetPresent = Boolean(observed.fleet_present);
  if (!runtimeObserved) return "inventory only";
  if (gatewayRegistered) return "gateway bound";
  if (configuredLocally || fleetPresent) return "runtime observed";
  return "shadow runtime";
}

export function deriveManifestRows(manifest: AgentBomManifestResponse, now: Date = new Date()): ManifestRow[] {
  const agentsByName = new Map<string, Record<string, unknown> | null>();
  const agentsByServer = new Map<string, Record<string, unknown>[]>();
  for (const agent of manifest.agents) {
    const row = asRecord(agent);
    for (const serverId of asStringList(row.mcp_server_ids)) {
      agentsByServer.set(serverId, [...(agentsByServer.get(serverId) ?? []), row]);
    }
    const name = asString(row.name);
    if (name) agentsByName.set(name, agentsByName.has(name) ? null : row);
  }

  return manifest.mcp_servers.map((server) => {
    const serverRow = asRecord(server);
    const tools = Array.isArray(serverRow.tools) ? serverRow.tools : [];
    const observed = asRecord(serverRow.observed);
    const observationNames = [...new Set(asStringList(serverRow.agent_names))];
    const legacyName = asString(serverRow.agent_name);
    if (!observationNames.length && legacyName) observationNames.push(legacyName);
    const observationName = observationNames.length === 1 ? observationNames[0] : "";
    const agentName = observationNames.join(", ") || "local discovery";
    const members = agentsByServer.get(asString(serverRow.id)) ?? [];
    const agent = members.length > 0
      ? (members.length === 1 ? members[0] : undefined)
      : observationName && serverRow.identity_basis !== "observation" ? agentsByName.get(observationName) : undefined;
    const security = asRecord(serverRow.security);
    const runtimeState = classifyRuntimeState(observed);
    const lastSeen = asString(observed.last_seen, "-");
    const credentialRefs = credentialNames(serverRow.credential_refs);
    const warnings = asStringList(security.warnings);
    const needsReview = Boolean(security.blocked) || warnings.length > 0 || runtimeState === "shadow runtime";
    const row = {
      id: asString(serverRow.id, asString(serverRow.name, "server")),
      agentName,
      owner: agent ? asString(agent.owner, "unowned") : "unknown",
      environment: asString(agent?.environment, "unknown"),
      name: asString(serverRow.name, "unnamed"),
      transport: asString(serverRow.transport, "unknown"),
      authMode: asString(serverRow.auth_mode, "unknown"),
      source: rowSource(serverRow, observed, manifest),
      toolCount: typeof serverRow.tool_count === "number"
        ? asNumber(serverRow.tool_count)
        : Array.isArray(serverRow.tools) ? tools.length : null,
      credentialRefs,
      runtimeState,
      freshness: classifyFreshness(lastSeen, now),
      reviewStatus: needsReview ? "review needed" as const : "not assessed" as const,
      lastSeen,
      warnings,
      reviewIndicators: [
        ...(security.blocked ? ["Security block reported"] : []),
        ...warnings,
        ...(runtimeState === "shadow runtime" ? ["Runtime observed without configured or fleet inventory"] : []),
        ...(credentialRefs.length ? [`${credentialRefs.length} credential reference${credentialRefs.length === 1 ? "" : "s"}`] : []),
      ],
    };
    return row;
  });
}

export function filterManifestRows(rows: ManifestRow[], filters: ManifestFilters): ManifestRow[] {
  const queryTokens = filters.query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return rows.filter((row) => {
    const haystack = `${row.agentName} ${row.owner} ${row.environment} ${row.name} ${row.transport} ${row.authMode} ${row.runtimeState} ${row.source}`
      .toLowerCase();
    return (
      (queryTokens.length === 0 || queryTokens.every((token) => haystack.includes(token))) &&
      (filters.source === "all" || row.source === filters.source) &&
      (filters.owner === "all" || row.owner === filters.owner) &&
      (filters.review === "all" || row.reviewStatus === filters.review) &&
      (filters.freshness === "all" || row.freshness === filters.freshness) &&
      (filters.runtime === "all" || row.runtimeState === filters.runtime)
    );
  });
}

export function manifestFilterOptions(rows: ManifestRow[]) {
  return {
    sources: [...new Set(rows.map((row) => row.source).filter(Boolean))].sort(),
    owners: [...new Set(rows.map((row) => row.owner).filter(Boolean))].sort(),
  };
}
