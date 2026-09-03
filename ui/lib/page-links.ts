type QueryValue = string | number | boolean | null | undefined;

function buildHref(path: string, values: ReadonlyArray<readonly [string, QueryValue]>): string {
  const params = new URLSearchParams();
  for (const [key, raw] of values) {
    if (raw == null) continue;
    const value = String(raw).trim();
    if (!value) continue;
    params.set(key, value);
  }
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function findingsHref(input: {
  q?: string | undefined;
  cve?: string | undefined;
  agent?: string | undefined;
  scan?: string | undefined;
  issue?: "vulnerability" | "misconfiguration" | "secret" | "pii" | "all";
} = {}): string {
  return buildHref("/findings", [
    ["q", input.q],
    ["cve", input.cve],
    ["agent", input.agent],
    ["scan", input.scan],
    ["issue", input.issue],
  ]);
}

export function securityGraphHref(input: {
  scan?: string | undefined;
  cve?: string | undefined;
  packageName?: string | undefined;
  agent?: string | undefined;
  node?: string | undefined;
  finding?: string | undefined;
  path?: string | undefined;
} = {}): string {
  const hasAttackPathFocus = Boolean(
    input.cve || input.packageName || input.agent || input.node || input.finding || input.path,
  );
  return buildHref("/security-graph", [
    ["lens", hasAttackPathFocus ? "attack-path" : undefined],
    ["scan", input.scan],
    ["cve", input.cve],
    ["package", input.packageName],
    ["agent", input.agent],
    ["node", input.node],
    ["finding", input.finding],
    ["path", input.path],
  ]);
}

export function complianceHref(input: { q?: string | undefined; scan?: string | undefined } = {}): string {
  return buildHref("/compliance", [["q", input.q], ["scan", input.scan]]);
}

export function remediationHref(input: {
  q?: string | undefined;
  correlation?: string | undefined;
  scan?: string | undefined;
  finding?: string | undefined;
  cve?: string | undefined;
  packageName?: string | undefined;
  path?: string | undefined;
} = {}): string {
  return buildHref("/remediation", [
    ["q", input.q],
    ["correlation", input.correlation],
    ["scan", input.scan],
    ["finding", input.finding],
    ["cve", input.cve],
    ["package", input.packageName],
    ["path", input.path],
  ]);
}

const GRAPH_LAYERS = new Set([
  "provider", "agent", "org", "account", "user", "group", "role", "policy",
  "serviceAccount", "servicePrincipal", "federatedIdentity", "environment", "fleet",
  "cluster", "server", "sharedServer", "package", "model", "framework", "dataset",
  "container", "cloudResource", "vulnerability", "misconfiguration", "credential", "tool",
  "managedIdentity", "accessGrant", "accessPolicy", "driftIncident", "dataStore",
]);

const GRAPH_LAYER_ALIASES: Readonly<Record<string, string>> = {
  service_account: "serviceAccount",
  service_principal: "servicePrincipal",
  federated_identity: "federatedIdentity",
  cloud_resource: "cloudResource",
  managed_identity: "managedIdentity",
  access_grant: "accessGrant",
  access_policy: "accessPolicy",
  drift_incident: "driftIncident",
  data_store: "dataStore",
};

export function graphLayerHref(entityKind: string): string {
  const normalized = entityKind.trim();
  const layer = GRAPH_LAYER_ALIASES[normalized] ?? normalized;
  return GRAPH_LAYERS.has(layer) ? buildHref("/graph", [["layers", layer]]) : "/graph";
}
