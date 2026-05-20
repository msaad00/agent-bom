import type { AgentBomManifestResponse } from "./api";

export type ManifestRiskFilter = "all" | "high" | "medium" | "low";
export type ManifestFreshnessFilter = "all" | "seen_24h" | "seen_7d" | "stale" | "unknown";
export type ManifestRuntimeFilter = "all" | "gateway bound" | "runtime observed" | "shadow runtime" | "inventory only";

export interface ManifestFilters {
  query: string;
  source: string;
  owner: string;
  risk: ManifestRiskFilter;
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
  toolCount: number;
  credentialRefs: string[];
  runtimeState: ManifestRuntimeFilter;
  freshness: Exclude<ManifestFreshnessFilter, "all">;
  riskLevel: ManifestRiskFilter;
  lastSeen: string;
  warnings: string[];
}

const RISKY_CREDENTIAL_TOKENS = ["admin", "root", "prod", "token", "key", "secret", "password"];

export const DEFAULT_MANIFEST_FILTERS: ManifestFilters = {
  query: "",
  source: "all",
  owner: "all",
  risk: "all",
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

function classifyRisk(row: {
  credentialRefs: string[];
  runtimeState: ManifestRow["runtimeState"];
  warnings: string[];
}): ManifestRiskFilter {
  const hasRiskyCredential = row.credentialRefs.some((ref) =>
    RISKY_CREDENTIAL_TOKENS.some((token) => ref.toLowerCase().includes(token)),
  );
  if (row.runtimeState === "shadow runtime" || row.warnings.length > 0 || hasRiskyCredential) {
    return "high";
  }
  if (row.credentialRefs.length > 0 || row.runtimeState === "runtime observed") {
    return "medium";
  }
  return "low";
}

export function deriveManifestRows(manifest: AgentBomManifestResponse, now: Date = new Date()): ManifestRow[] {
  const agentsByName = new Map(
    manifest.agents.map((agent) => {
      const row = asRecord(agent);
      return [asString(row.name), row] as const;
    }),
  );
  const agentsById = new Map(
    manifest.agents.map((agent) => {
      const row = asRecord(agent);
      return [asString(row.id, asString(row.canonical_id)), row] as const;
    }),
  );

  return manifest.mcp_servers.map((server) => {
    const serverRow = asRecord(server);
    const tools = Array.isArray(serverRow.tools) ? serverRow.tools : [];
    const observed = asRecord(serverRow.observed);
    const agentName = asString(serverRow.agent_name, "local discovery");
    const agent = agentsByName.get(agentName) ?? agentsById.get(agentName) ?? {};
    const security = asRecord(serverRow.security);
    const runtimeState = classifyRuntimeState(observed);
    const lastSeen = asString(observed.last_seen, "-");
    const row = {
      id: asString(serverRow.id, asString(serverRow.name, "server")),
      agentName,
      owner: asString(agent.owner, "unowned"),
      environment: asString(agent.environment, "unknown"),
      name: asString(serverRow.name, "unnamed"),
      transport: asString(serverRow.transport, "unknown"),
      authMode: asString(serverRow.auth_mode, "unknown"),
      source: rowSource(serverRow, observed, manifest),
      toolCount: asNumber(serverRow.tool_count) || tools.length,
      credentialRefs: credentialNames(serverRow.credential_refs),
      runtimeState,
      freshness: classifyFreshness(lastSeen, now),
      riskLevel: "low" as ManifestRiskFilter,
      lastSeen,
      warnings: asStringList(security.warnings),
    };
    return { ...row, riskLevel: classifyRisk(row) };
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
      (filters.risk === "all" || row.riskLevel === filters.risk) &&
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
