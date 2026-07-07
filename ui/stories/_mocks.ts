// Shared, representative mock data for the dashboard component stories.
// Kept deliberately hand-authored (not fetched) so stories stay deterministic
// and exercise loading / empty / dense / permission-denied states on demand.
import type { ComplianceControl, ComplianceResponse } from "@/lib/api";
import type { EnrichedVuln } from "@/lib/findings-view";
import type { ExposurePath } from "@/lib/exposure-path";
import type { FindingTriageItem } from "@/lib/api";

export function makeVuln(overrides: Partial<EnrichedVuln> = {}): EnrichedVuln {
  return {
    id: "CVE-2026-0001",
    severity: "critical",
    summary: "Server-side template injection in the request routing layer.",
    description:
      "A crafted MCP tool invocation reaches an unsanitised template render, allowing remote code execution on the gateway host.",
    cvss_score: 9.8,
    epss_score: 0.912,
    is_kev: true,
    cisa_kev: true,
    fixed_version: "2.2.3",
    published: "2026-06-14T00:00:00Z",
    packages: ["werkzeug", "flask"],
    agents: ["analyst-agent", "ops-agent"],
    sources: ["osv", "nvd"],
    affected_servers: ["database", "filesystem"],
    exposed_credentials: ["DATABASE_URL", "AWS_SECRET_ACCESS_KEY"],
    reachable_tools: ["execute_sql", "read_file"],
    references: [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
      "https://osv.dev/vulnerability/CVE-2026-0001",
    ],
    advisory_sources: ["osv", "nvd"],
    remediation_items: [
      {
        package: "werkzeug",
        ecosystem: "pypi",
        current_version: "2.2.2",
        fixed_version: "2.2.3",
        action: "Upgrade werkzeug to 2.2.3",
        command: "pip install 'werkzeug==2.2.3'",
        verify_command: "pip show werkzeug",
        references: ["https://osv.dev/vulnerability/CVE-2026-0001"],
        risk_narrative:
          "Reachable from the analyst-agent tool closure via the database MCP server.",
      },
    ],
    graph_reachable: true,
    graph_min_hop_distance: 2,
    effective_reach_score: 88,
    effective_reach_band: "high",
    framework_tags: ["OWASP-LLM-01", "MITRE-ATLAS-AML.T0051"],
    runtime_evidence: { state: "observed", observed_count: 4, blocked_count: 1 },
    lifecycle_status: "open",
    first_seen: "2026-06-20T09:00:00Z",
    last_seen: "2026-07-05T18:30:00Z",
    scan_count: 7,
    ...overrides,
  };
}

export const denseVulns: EnrichedVuln[] = [
  makeVuln(),
  makeVuln({
    id: "CVE-2026-0114",
    severity: "high",
    cvss_score: 8.1,
    epss_score: 0.44,
    is_kev: false,
    cisa_kev: false,
    packages: ["requests"],
    agents: ["ops-agent"],
    affected_servers: ["http-fetch"],
    exposed_credentials: [],
    reachable_tools: ["fetch_url"],
    fixed_version: "2.32.4",
    graph_reachable: true,
    graph_min_hop_distance: 1,
    effective_reach_score: 61,
    effective_reach_band: "medium",
    lifecycle_status: "open",
    last_seen: "2026-07-04T12:00:00Z",
  }),
  makeVuln({
    id: "CVE-2025-8890",
    severity: "medium",
    cvss_score: 5.4,
    epss_score: 0.08,
    is_kev: false,
    cisa_kev: false,
    packages: ["pyyaml"],
    agents: [],
    affected_servers: [],
    exposed_credentials: [],
    reachable_tools: [],
    fixed_version: undefined,
    graph_reachable: false,
    graph_min_hop_distance: null,
    effective_reach_score: 12,
    effective_reach_band: "low",
    lifecycle_status: "resolved",
    resolved_at: "2026-07-01T00:00:00Z",
    last_seen: "2026-06-28T00:00:00Z",
  }),
  makeVuln({
    id: "CVE-2025-4412",
    severity: "low",
    cvss_score: 3.1,
    epss_score: 0.01,
    is_kev: false,
    cisa_kev: false,
    packages: ["urllib3"],
    agents: [],
    affected_servers: [],
    exposed_credentials: [],
    reachable_tools: [],
    fixed_version: "2.2.1",
    graph_reachable: null,
    lifecycle_status: "reopened",
    reopened_at: "2026-07-02T00:00:00Z",
    last_seen: "2026-07-03T00:00:00Z",
  }),
];

export function makeTriage(overrides: Partial<FindingTriageItem> = {}): FindingTriageItem {
  return {
    id: "triage-1",
    vulnerability_id: "CVE-2026-0001",
    package: "werkzeug",
    server_name: "database",
    queue_state: "in_review",
    decision: "under_investigation",
    justification: null,
    decision_reason: "Awaiting confirmation of reachable execute path.",
    assignee: "sec-oncall",
    created_by: "auto-triage",
    created_at: "2026-07-01T00:00:00Z",
    reviewed_at: "2026-07-05T00:00:00Z",
    expires_at: "2026-08-01T00:00:00Z",
    tenant_id: "acme",
    vex_eligible: true,
    ...overrides,
  };
}

export const exposurePath: ExposurePath = {
  id: "path-1",
  rank: 1,
  label: "analyst-agent -> database -> werkzeug -> CVE-2026-0001",
  summary:
    "The analyst agent can reach a critical, KEV-listed package through the database MCP server, which also exposes SQL execution and a live database credential.",
  riskScore: 9.6,
  severity: "critical",
  source: { id: "agent:analyst", label: "analyst-agent", role: "agent" },
  target: {
    id: "vuln:werkzeug:CVE-2026-0001",
    label: "CVE-2026-0001",
    role: "finding",
    severity: "critical",
  },
  hops: [
    { id: "agent:analyst", label: "analyst-agent", role: "agent" },
    { id: "server:database", label: "database", role: "server" },
    { id: "pkg:werkzeug", label: "werkzeug@2.2.2", role: "package", severity: "critical" },
    {
      id: "vuln:werkzeug:CVE-2026-0001",
      label: "CVE-2026-0001",
      role: "finding",
      severity: "critical",
    },
    { id: "tool:execute_sql", label: "execute_sql", role: "tool" },
    { id: "cred:DATABASE_URL", label: "DATABASE_URL", role: "credential" },
  ],
  relationships: [
    {
      id: "agent->server",
      source: "agent:analyst",
      target: "server:database",
      relationship: "uses",
      direction: "directed",
      traversable: true,
      confidence: "observed",
    },
    {
      id: "pkg->vuln",
      source: "pkg:werkzeug",
      target: "vuln:werkzeug:CVE-2026-0001",
      relationship: "vulnerable_to",
      direction: "directed",
      traversable: true,
      confidence: "scanner",
    },
  ],
  nodeIds: ["agent:analyst", "server:database", "pkg:werkzeug", "vuln:werkzeug:CVE-2026-0001"],
  edgeIds: ["agent->server", "pkg->vuln"],
  findings: ["CVE-2026-0001"],
  affectedAgents: ["analyst-agent"],
  affectedServers: ["database"],
  reachableTools: ["execute_sql"],
  exposedCredentials: ["DATABASE_URL"],
  dependencyContext: {
    packageName: "werkzeug",
    packageVersion: "2.2.2",
    ecosystem: "pypi",
    serverName: "database",
  },
  fix: { label: "Upgrade werkzeug", version: "2.2.3" },
  evidence: {
    cvssScore: 9.8,
    epssScore: 0.912,
    isKev: true,
    attackVectorSummary: "Database MCP server exposes SQL execution to the agent tool closure.",
  },
  timestamps: { firstSeen: "2026-06-20T09:00:00Z", lastSeen: "2026-07-05T18:30:00Z" },
};

function control(
  code: string,
  name: string,
  status: ComplianceControl["status"],
  breakdown: Partial<Record<"critical" | "high" | "medium" | "low", number>> = {},
): ComplianceControl {
  const findings =
    (breakdown.critical ?? 0) +
    (breakdown.high ?? 0) +
    (breakdown.medium ?? 0) +
    (breakdown.low ?? 0);
  return {
    code,
    name,
    status,
    findings,
    severity_breakdown: {
      critical: breakdown.critical ?? 0,
      high: breakdown.high ?? 0,
      medium: breakdown.medium ?? 0,
      low: breakdown.low ?? 0,
    },
    affected_packages: findings > 0 ? ["werkzeug", "requests"].slice(0, Math.min(2, findings)) : [],
    affected_agents: findings > 0 ? ["analyst-agent"] : [],
  };
}

// Only the fields the ComplianceMatrix component reads are populated; the rest
// of the wide API response shape is filled with empty catalogs and cast.
export function makeCompliance(overrides: Partial<ComplianceResponse> = {}): ComplianceResponse {
  const base = {
    overall_score: 72,
    overall_status: "warning",
    scan_count: 12,
    latest_scan: "2026-07-05T18:30:00Z",
    has_mcp_context: true,
    has_agent_context: true,
    scan_sources: ["cli", "runtime"],
    owasp_llm_top10: [
      control("LLM01", "Prompt Injection", "fail", { critical: 1, high: 2 }),
      control("LLM02", "Insecure Output Handling", "warning", { medium: 3 }),
      control("LLM06", "Sensitive Information Disclosure", "pass"),
    ],
    owasp_mcp_top10: [
      control("MCP01", "Tool Poisoning", "fail", { critical: 1 }),
      control("MCP04", "Credential Exposure", "warning", { high: 1, medium: 1 }),
    ],
    owasp_agentic_top10: [
      control("AA01", "Agent Authorization Hijacking", "warning", { high: 1 }),
      control("AA05", "Cascading Failures", "pass"),
    ],
    mitre_atlas: [
      control("AML.T0051", "LLM Prompt Injection", "fail", { critical: 1, high: 1 }),
      control("AML.T0057", "LLM Data Leakage", "pass"),
    ],
    nist_ai_rmf: [
      control("MEASURE-2.7", "Security & Resilience", "warning", { medium: 2 }),
      control("GOVERN-1.1", "Legal & Regulatory", "pass"),
    ],
    eu_ai_act: [
      control("ART-15", "Accuracy, Robustness & Cybersecurity", "warning", { high: 1 }),
      control("ART-9", "Risk Management System", "pass"),
    ],
  };
  return { ...base, ...overrides } as ComplianceResponse;
}

export const emptyCompliance = makeCompliance({
  overall_score: 100,
  overall_status: "pass",
  owasp_llm_top10: [control("LLM01", "Prompt Injection", "pass")],
  owasp_mcp_top10: [control("MCP01", "Tool Poisoning", "pass")],
  owasp_agentic_top10: [control("AA01", "Agent Authorization Hijacking", "pass")],
  mitre_atlas: [control("AML.T0051", "LLM Prompt Injection", "pass")],
  nist_ai_rmf: [control("GOVERN-1.1", "Legal & Regulatory", "pass")],
  eu_ai_act: [control("ART-9", "Risk Management System", "pass")],
});
