#!/usr/bin/env node
import { chromium } from "@playwright/test";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const REPO_ROOT = path.resolve(UI_ROOT, "..");
const IMAGE_DIR = path.join(REPO_ROOT, "docs", "images");
const VERSION = "0.88.5";
const CREATED_AT = "2026-06-03T20:30:00Z";
const SCAN_ID = "scan-proof-ai-platform";
const PREVIOUS_SCAN_ID = "scan-proof-ai-platform-prev";

const baseUrlFromEnv = process.env.CAPTURE_BASE_URL;
const PORT = Number(process.env.CAPTURE_PORT || "3137");
const BASE_URL = baseUrlFromEnv || `http://127.0.0.1:${PORT}`;

function severityId(severity) {
  return { none: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity] ?? 0;
}

function node(id, entityType, label, severity = "none", riskScore = 0, attributes = {}) {
  return {
    id,
    entity_type: entityType,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: riskScore,
    severity,
    severity_id: severityId(severity),
    first_seen: CREATED_AT,
    last_seen: CREATED_AT,
    attributes,
    compliance_tags: attributes.compliance_tags ?? [],
    data_sources: attributes.data_sources ?? ["demo-scan", "gateway-runtime", "fleet-sync"],
    dimensions: {
      owner: String(attributes.owner ?? "platform-security"),
      environment: String(attributes.environment ?? "prod"),
    },
  };
}

function edge(source, target, relationship, weight = 1, evidence = {}) {
  return {
    id: `${source}->${target}:${relationship}`,
    source,
    target,
    relationship,
    direction: "directed",
    weight,
    traversable: true,
    first_seen: CREATED_AT,
    last_seen: CREATED_AT,
    evidence,
    activity_id: 1,
  };
}

function buildGraph() {
  const nodes = [
    node("provider:aws-prod", "provider", "AWS prod account", "medium", 5.4, { environment: "prod", owner: "cloud-platform" }),
    node("env:prod-ai", "environment", "prod-ai-control-plane", "high", 7.8, { environment: "prod", owner: "ai-platform" }),
    node("cluster:eks-ai", "cluster", "eks-ai-runtime", "high", 7.5, { environment: "prod", owner: "platform-security" }),
    node("container:agent-gateway", "container", "agent-gateway:0.88.5", "high", 7.6, { image: "agent-bom/gateway:0.88.5" }),
    node("agent:developer-copilot", "agent", "developer-copilot", "critical", 9.4, { agent_type: "ide", owner: "platform-security", environment: "prod" }),
    node("agent:sre-runbook", "agent", "sre-runbook-agent", "high", 8.6, { agent_type: "runbook", owner: "sre", environment: "prod" }),
    node("agent:finance-rag", "agent", "finance-rag-agent", "high", 8.2, { agent_type: "rag", owner: "finance-data", environment: "prod" }),
    node("user:contractor", "user", "contractor-reviewer", "high", 8.4, { owner: "identity", environment: "prod" }),
    node("sa:jit-review", "service_account", "jit-prod-reviewer", "high", 8.1, { owner: "identity", environment: "prod" }),
    node("role:prod-admin", "role", "prod-ai-admin", "critical", 9.2, { owner: "identity", environment: "prod" }),
    node("policy:gateway-default-deny", "policy", "default-deny gateway policy", "medium", 4.8, { owner: "platform-security" }),
    node("server:github", "server", "github-enterprise MCP", "critical", 9.1, { transport: "sse", registry_verified: true }),
    node("server:filesystem", "server", "filesystem MCP", "critical", 9.0, { transport: "stdio", scope: "/workspace/prod" }),
    node("server:snowflake", "server", "snowflake-rag MCP", "high", 8.4, { transport: "sse", scope: "finance_warehouse" }),
    node("server:slack", "server", "incident-slack MCP", "high", 7.8, { transport: "sse" }),
    node("tool:repo-write", "tool", "create_pull_request", "high", 8.2, { tool_class: "repo-write" }),
    node("tool:exec", "tool", "execute_command", "critical", 9.5, { tool_class: "shell" }),
    node("tool:query", "tool", "run_sql", "high", 8.3, { tool_class: "data-query" }),
    node("tool:post", "tool", "post_incident_update", "medium", 4.8, { tool_class: "messaging" }),
    node("cred:github", "credential", "GITHUB_FINE_GRAINED_TOKEN", "critical", 9.1, { safe_to_store: false }),
    node("cred:snowflake", "credential", "SNOWFLAKE_PROD_KEY", "critical", 9.3, { safe_to_store: false }),
    node("cred:aws", "credential", "AWS_ROLE_SESSION", "high", 8.1, { safe_to_store: false }),
    node("pkg:next", "package", "next@16.2.6", "critical", 9.2, { ecosystem: "npm", version: "16.2.6" }),
    node("pkg:urllib3", "package", "urllib3@2.4.0", "high", 8.5, { ecosystem: "pypi", version: "2.4.0" }),
    node("pkg:protobuf", "package", "protobuf@6.33.2", "high", 8.0, { ecosystem: "pypi", version: "6.33.2" }),
    node("pkg:langchain", "package", "langchain@0.3.21", "medium", 5.8, { ecosystem: "pypi", version: "0.3.21" }),
    node("cve:next", "vulnerability", "CVE-2026-21441", "critical", 9.8, { cvss_score: 9.8, epss_score: 0.82, is_kev: true }),
    node("cve:urllib3", "vulnerability", "CVE-2026-32597", "high", 8.8, { cvss_score: 8.8, epss_score: 0.51 }),
    node("cve:protobuf", "vulnerability", "CVE-2026-0994", "high", 8.1, { cvss_score: 8.1, epss_score: 0.38 }),
    node("dataset:finance-docs", "dataset", "finance-board-rag-index", "high", 8.0, { data_classification: "confidential" }),
    node("model:gpt-prod", "model", "prod-reasoning-model", "medium", 4.8, { provider: "customer-managed" }),
  ];

  const edges = [
    edge("provider:aws-prod", "env:prod-ai", "hosts"),
    edge("env:prod-ai", "cluster:eks-ai", "hosts"),
    edge("cluster:eks-ai", "container:agent-gateway", "hosts"),
    edge("container:agent-gateway", "policy:gateway-default-deny", "manages"),
    edge("user:contractor", "sa:jit-review", "acted_as"),
    edge("sa:jit-review", "role:prod-admin", "assumes"),
    edge("role:prod-admin", "agent:developer-copilot", "can_access"),
    edge("agent:developer-copilot", "server:github", "uses"),
    edge("agent:developer-copilot", "server:filesystem", "uses"),
    edge("agent:sre-runbook", "server:filesystem", "uses"),
    edge("agent:sre-runbook", "server:slack", "uses"),
    edge("agent:finance-rag", "server:snowflake", "uses"),
    edge("agent:finance-rag", "server:slack", "uses"),
    edge("agent:developer-copilot", "agent:sre-runbook", "shares_server"),
    edge("agent:sre-runbook", "agent:finance-rag", "shares_cred"),
    edge("server:github", "tool:repo-write", "provides_tool"),
    edge("server:filesystem", "tool:exec", "provides_tool"),
    edge("server:snowflake", "tool:query", "provides_tool"),
    edge("server:slack", "tool:post", "provides_tool"),
    edge("server:github", "cred:github", "exposes_cred"),
    edge("server:snowflake", "cred:snowflake", "exposes_cred"),
    edge("server:filesystem", "cred:aws", "exposes_cred"),
    edge("server:github", "pkg:next", "depends_on"),
    edge("server:filesystem", "pkg:urllib3", "depends_on"),
    edge("server:snowflake", "pkg:protobuf", "depends_on"),
    edge("server:snowflake", "pkg:langchain", "depends_on"),
    edge("pkg:next", "cve:next", "vulnerable_to", 1.6, { cvss_score: 9.8, epss_score: 0.82, is_kev: true }),
    edge("pkg:urllib3", "cve:urllib3", "vulnerable_to", 1.4, { cvss_score: 8.8, epss_score: 0.51 }),
    edge("pkg:protobuf", "cve:protobuf", "vulnerable_to", 1.2, { cvss_score: 8.1, epss_score: 0.38 }),
    edge("server:snowflake", "dataset:finance-docs", "accessed"),
    edge("agent:finance-rag", "model:gpt-prod", "uses"),
    edge("policy:gateway-default-deny", "tool:exec", "manages"),
  ];
  const edgeIdsFor = (hops) =>
    hops.slice(0, -1).map((source, index) => {
      const target = hops[index + 1];
      return edges.find((item) => item.source === source && item.target === target)?.id ?? `${source}->${target}:related`;
    });

  const attackPaths = [
    {
      source: "user:contractor",
      target: "cve:next",
      hops: ["user:contractor", "sa:jit-review", "role:prod-admin", "agent:developer-copilot", "server:github", "pkg:next", "cve:next"],
      edges: edgeIdsFor(["user:contractor", "sa:jit-review", "role:prod-admin", "agent:developer-copilot", "server:github", "pkg:next", "cve:next"]),
      composite_risk: 9.8,
      summary: "JIT reviewer identity can reach a critical Next.js exposure through developer-copilot and GitHub MCP.",
      credential_exposure: ["GITHUB_FINE_GRAINED_TOKEN"],
      tool_exposure: ["create_pull_request"],
      vuln_ids: ["CVE-2026-21441"],
    },
    {
      source: "agent:sre-runbook",
      target: "cve:urllib3",
      hops: ["agent:sre-runbook", "server:filesystem", "pkg:urllib3", "cve:urllib3"],
      edges: edgeIdsFor(["agent:sre-runbook", "server:filesystem", "pkg:urllib3", "cve:urllib3"]),
      composite_risk: 8.9,
      summary: "SRE runbook agent reaches filesystem MCP command tooling through vulnerable urllib3.",
      credential_exposure: ["AWS_ROLE_SESSION"],
      tool_exposure: ["execute_command"],
      vuln_ids: ["CVE-2026-32597"],
    },
    {
      source: "agent:finance-rag",
      target: "dataset:finance-docs",
      hops: ["agent:finance-rag", "server:snowflake", "cred:snowflake", "dataset:finance-docs"],
      edges: edgeIdsFor(["agent:finance-rag", "server:snowflake", "cred:snowflake", "dataset:finance-docs"]),
      composite_risk: 8.4,
      summary: "Finance RAG agent can query confidential board material through Snowflake MCP and a production key reference.",
      credential_exposure: ["SNOWFLAKE_PROD_KEY"],
      tool_exposure: ["run_sql"],
      vuln_ids: ["CVE-2026-0994"],
    },
  ];

  const stats = {
    total_nodes: nodes.length,
    total_edges: edges.length,
    node_types: nodes.reduce((acc, item) => ({ ...acc, [item.entity_type]: (acc[item.entity_type] ?? 0) + 1 }), {}),
    severity_counts: { critical: 9, high: 13, medium: 4, low: 0 },
    relationship_types: edges.reduce((acc, item) => ({ ...acc, [item.relationship]: (acc[item.relationship] ?? 0) + 1 }), {}),
    attack_path_count: attackPaths.length,
    interaction_risk_count: 4,
    max_attack_path_risk: 9.8,
    highest_interaction_risk: 8.8,
  };

  return {
    scan_id: SCAN_ID,
    tenant_id: "default",
    created_at: CREATED_AT,
    nodes,
    edges,
    attack_paths: attackPaths,
    interaction_risks: [],
    stats,
    pagination: { total: nodes.length, offset: 0, limit: nodes.length, has_more: false },
  };
}

const graph = buildGraph();

function contextGraph() {
  const nodes = [
    { id: "agent:developer-copilot", kind: "agent", label: "developer-copilot", metadata: { severity: "critical", agent_type: "ide" } },
    { id: "agent:sre-runbook", kind: "agent", label: "sre-runbook-agent", metadata: { severity: "high", agent_type: "runbook" } },
    { id: "agent:finance-rag", kind: "agent", label: "finance-rag-agent", metadata: { severity: "high", agent_type: "rag" } },
    { id: "iam:jit-review", kind: "iam_role", entity_type: "service_account", label: "jit-prod-reviewer", metadata: { severity: "high" } },
    { id: "server:github", kind: "server", label: "github-enterprise MCP", metadata: { severity: "critical" } },
    { id: "server:filesystem", kind: "server", label: "filesystem MCP", metadata: { severity: "critical" } },
    { id: "server:snowflake", kind: "server", label: "snowflake-rag MCP", metadata: { severity: "high" } },
    { id: "cred:github", kind: "credential", label: "GITHUB_FINE_GRAINED_TOKEN", metadata: { severity: "critical" } },
    { id: "cred:snowflake", kind: "credential", label: "SNOWFLAKE_PROD_KEY", metadata: { severity: "critical" } },
    { id: "tool:repo-write", kind: "tool", label: "create_pull_request", metadata: { severity: "high" } },
    { id: "tool:exec", kind: "tool", label: "execute_command", metadata: { severity: "critical" } },
    { id: "tool:query", kind: "tool", label: "run_sql", metadata: { severity: "high" } },
    { id: "cve:next", kind: "vulnerability", label: "CVE-2026-21441", metadata: { severity: "critical", cvss_score: 9.8, epss_score: 0.82, is_kev: true } },
    { id: "cve:urllib3", kind: "vulnerability", label: "CVE-2026-32597", metadata: { severity: "high", cvss_score: 8.8, epss_score: 0.51 } },
  ];
  const edges = [
    { source: "iam:jit-review", target: "agent:developer-copilot", kind: "member_of", relationship: "member_of", weight: 1, metadata: {} },
    { source: "agent:developer-copilot", target: "server:github", kind: "uses", relationship: "uses", weight: 1, metadata: { effective_reach_score: 9.4 } },
    { source: "agent:developer-copilot", target: "server:filesystem", kind: "uses", relationship: "uses", weight: 1, metadata: { effective_reach_score: 9.1 } },
    { source: "server:github", target: "cred:github", kind: "exposes_cred", relationship: "exposes_cred", weight: 1, metadata: { effective_reach_score: 9.2 } },
    { source: "server:github", target: "tool:repo-write", kind: "provides_tool", relationship: "provides_tool", weight: 1, metadata: { effective_reach_score: 8.3 } },
    { source: "server:github", target: "cve:next", kind: "vulnerable_to", relationship: "vulnerable_to", weight: 1, metadata: { effective_reach_score: 9.8 } },
    { source: "server:filesystem", target: "tool:exec", kind: "provides_tool", relationship: "provides_tool", weight: 1, metadata: { effective_reach_score: 9.5 } },
    { source: "server:filesystem", target: "cve:urllib3", kind: "vulnerable_to", relationship: "vulnerable_to", weight: 1, metadata: { effective_reach_score: 8.8 } },
    { source: "agent:sre-runbook", target: "server:filesystem", kind: "uses", relationship: "uses", weight: 1, metadata: { effective_reach_score: 8.5 } },
    { source: "agent:finance-rag", target: "server:snowflake", kind: "uses", relationship: "uses", weight: 1, metadata: { effective_reach_score: 8.4 } },
    { source: "server:snowflake", target: "cred:snowflake", kind: "exposes_cred", relationship: "exposes_cred", weight: 1, metadata: { effective_reach_score: 9.0 } },
    { source: "server:snowflake", target: "tool:query", kind: "provides_tool", relationship: "provides_tool", weight: 1, metadata: { effective_reach_score: 8.4 } },
    { source: "agent:developer-copilot", target: "agent:sre-runbook", kind: "shares_server", relationship: "shares_server", weight: 1, metadata: { server: "filesystem MCP" } },
    { source: "agent:sre-runbook", target: "agent:finance-rag", kind: "shares_credential", relationship: "shares_credential", weight: 1, metadata: { credential: "shared incident webhook" } },
  ];
  return {
    nodes,
    edges,
    lateral_paths: [
      {
        source: "agent:developer-copilot",
        target: "cve:next",
        hops: ["agent:developer-copilot", "server:github", "cred:github", "tool:repo-write", "cve:next"],
        edges: [],
        composite_risk: 9.8,
        summary: "developer-copilot reaches GitHub MCP, a repo-write tool, a credential reference, and a critical CVE in one bounded path.",
        credential_exposure: ["GITHUB_FINE_GRAINED_TOKEN"],
        tool_exposure: ["create_pull_request"],
        vuln_ids: ["CVE-2026-21441"],
      },
      {
        source: "agent:developer-copilot",
        target: "agent:sre-runbook",
        hops: ["agent:developer-copilot", "server:filesystem", "tool:exec", "agent:sre-runbook"],
        edges: [],
        composite_risk: 8.9,
        summary: "Shared filesystem MCP creates a lateral path from IDE agent scope to SRE runbook automation.",
        credential_exposure: ["AWS_ROLE_SESSION"],
        tool_exposure: ["execute_command"],
        vuln_ids: ["CVE-2026-32597"],
      },
    ],
    interaction_risks: [
      {
        pattern: "shared_server_lateral_path",
        agents: ["developer-copilot", "sre-runbook-agent"],
        risk_score: 8.9,
        description: "Two high-trust agents share filesystem MCP command tooling; scope narrowing is the lowest-cost choke point.",
        owasp_agentic_tag: "LLM06",
      },
      {
        pattern: "credential_reuse",
        agents: ["sre-runbook-agent", "finance-rag-agent"],
        risk_score: 8.2,
        description: "Incident workflow and RAG workflow share a credential-bearing messaging path.",
        owasp_agentic_tag: "LLM05",
      },
    ],
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      agent_count: 3,
      shared_server_count: 2,
      shared_credential_count: 2,
      lateral_path_count: 2,
      max_lateral_depth: 4,
      highest_path_risk: 9.8,
      interaction_risk_count: 2,
    },
  };
}

function scanJob() {
  return {
    job_id: SCAN_ID,
    status: "done",
    created_at: CREATED_AT,
    request: {},
    progress: [],
    result: {
      agents: [
        { name: "developer-copilot", agent_type: "ide", mcp_servers: [] },
        { name: "sre-runbook-agent", agent_type: "runbook", mcp_servers: [] },
        { name: "finance-rag-agent", agent_type: "rag", mcp_servers: [] },
      ],
      blast_radius: [],
      scan_sources: ["demo-scan", "fleet-sync", "gateway-runtime"],
    },
  };
}

const fleetAgents = [
  {
    agent_id: "agent:developer-copilot",
    name: "developer-copilot",
    agent_type: "ide",
    config_path: "/workspace/prod/.cursor/mcp.json",
    lifecycle_state: "quarantined",
    owner: "platform-security",
    environment: "prod-ai-control-plane",
    tags: ["prod", "repo-write", "jit-review"],
    trust_score: 38,
    trust_factors: { critical_findings: 4, exposed_credentials: 2, unverified_tools: 1, runtime_policy_hits: 7 },
    server_count: 2,
    package_count: 48,
    credential_count: 2,
    vuln_count: 9,
    last_discovery: CREATED_AT,
    last_scan: CREATED_AT,
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    notes: "Auto-quarantined after JIT identity path reached repo-write MCP tooling.",
  },
  {
    agent_id: "agent:sre-runbook",
    name: "sre-runbook-agent",
    agent_type: "runbook",
    config_path: "/ops/runbooks/mcp.json",
    lifecycle_state: "pending_review",
    owner: "sre",
    environment: "prod-ai-control-plane",
    tags: ["prod", "command-tooling"],
    trust_score: 54,
    trust_factors: { command_tools: 2, shared_servers: 1, high_findings: 3 },
    server_count: 2,
    package_count: 35,
    credential_count: 1,
    vuln_count: 5,
    last_discovery: CREATED_AT,
    last_scan: CREATED_AT,
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    notes: "Needs command scope review before approval.",
  },
  {
    agent_id: "agent:finance-rag",
    name: "finance-rag-agent",
    agent_type: "rag",
    config_path: "/finance/rag/mcp.json",
    lifecycle_state: "approved",
    owner: "finance-data",
    environment: "prod-finance",
    tags: ["prod", "rag", "confidential-data"],
    trust_score: 74,
    trust_factors: { data_access: 3, credential_refs: 1, approved_owner: 1 },
    server_count: 2,
    package_count: 41,
    credential_count: 1,
    vuln_count: 3,
    last_discovery: CREATED_AT,
    last_scan: CREATED_AT,
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    notes: "Approved with Snowflake read-only policy.",
  },
  {
    agent_id: "agent:security-analyst",
    name: "security-analyst-agent",
    agent_type: "analyst",
    config_path: "/security/mcp.json",
    lifecycle_state: "approved",
    owner: "security",
    environment: "staging",
    tags: ["staging", "read-only"],
    trust_score: 86,
    trust_factors: { read_only_tools: 5, no_credentials: 1 },
    server_count: 1,
    package_count: 14,
    credential_count: 0,
    vuln_count: 1,
    last_discovery: CREATED_AT,
    last_scan: CREATED_AT,
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    notes: "Approved read-only analyst surface.",
  },
];

function fixFirstView() {
  const cards = graph.attack_paths.map((pathItem, index) => ({
    id: `fix-${index + 1}`,
    rank: index + 1,
    title: [
      "JIT identity reaches repo-write MCP and critical CVE",
      "Runbook agent reaches shell tooling and vulnerable dependency",
      "RAG agent reaches confidential dataset through Snowflake key",
    ][index],
    summary: pathItem.summary,
    attack_path: pathItem,
    nodes: graph.nodes,
    sequence_labels: pathItem.hops.map((hop) => graph.nodes.find((item) => item.id === hop)?.label ?? hop),
    risk_reasons: [
      { kind: "effective_reach", label: "Reachable", detail: "Graph traversal connects identity, agent, server, tool, package, and finding." },
      { kind: "credential_exposure", label: "Credential", detail: "The path includes a safe-to-store credential reference." },
      { kind: "runtime_policy", label: "Policy hit", detail: "Gateway policy has evaluated this tool class in advisory or blocking mode." },
    ],
    next_actions: [
      { title: "Narrow tool scope", detail: "Disable or scope the highest-risk MCP tool on this path.", href: "/gateway" },
      { title: "Open remediation", detail: "Patch the vulnerable package and regenerate graph evidence.", href: "/remediation" },
    ],
    affected: {
      agents: pathItem.hops.filter((hop) => hop.startsWith("agent:")),
      servers: pathItem.hops.filter((hop) => hop.startsWith("server:")),
      packages: pathItem.hops.filter((hop) => hop.startsWith("pkg:")),
      findings: pathItem.vuln_ids,
      credentials: pathItem.credential_exposure,
      tools: pathItem.tool_exposure,
    },
  }));
  return {
    scan_id: SCAN_ID,
    tenant_id: "default",
    created_at: CREATED_AT,
    cards,
    summary: {
      total_paths: 12,
      matched_paths: cards.length,
      returned_paths: cards.length,
      highest_risk: 9.8,
      covered_findings: 3,
      node_count: graph.nodes.length,
      edge_count: graph.edges.length,
    },
    focus: { cve: "", package: "", agent: "" },
  };
}

const gatewayPolicies = [
  {
    policy_id: "policy-default-deny",
    name: "Default-deny prod MCP runtime",
    description: "Blocks shell and write-capable tools unless an approved JIT grant and environment match exist.",
    mode: "enforce",
    rules: [
      { id: "block-shell", description: "Block command execution tools outside approved runbooks", action: "block", block_tools: ["execute_command", "shell", "exec"], tool_name: null, tool_name_pattern: ".*(exec|shell|command).*", arg_pattern: {}, rate_limit: null, require_registry_verified: false },
      { id: "block-repo-write", description: "Block repository write tools for unreviewed agents", action: "block", block_tools: ["create_pull_request", "write_file"], tool_name: null, tool_name_pattern: ".*(write|pull_request).*", arg_pattern: {}, rate_limit: null, require_registry_verified: true },
      { id: "watch-secret-paths", description: "Alert on tools touching credential or secret paths", action: "warn", block_tools: [], tool_name: null, tool_name_pattern: ".*", arg_pattern: { path: ".*(secret|token|credential).*" }, rate_limit: null, require_registry_verified: false },
    ],
    bound_agents: ["developer-copilot", "sre-runbook-agent"],
    bound_agent_types: ["ide", "runbook"],
    bound_environments: ["prod-ai-control-plane"],
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    enabled: true,
  },
  {
    policy_id: "policy-rag-readonly",
    name: "Finance RAG read-only data boundary",
    description: "Allows Snowflake query tools only when scoped to approved warehouse roles.",
    mode: "audit",
    rules: [
      { id: "readonly-snowflake", description: "Audit SQL tool use against approved read-only role", action: "warn", block_tools: [], tool_name: "run_sql", tool_name_pattern: null, arg_pattern: { role: "FINANCE_READONLY" }, rate_limit: 120, require_registry_verified: true },
    ],
    bound_agents: ["finance-rag-agent"],
    bound_agent_types: ["rag"],
    bound_environments: ["prod-finance"],
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    enabled: true,
  },
];

const gatewayAudit = [
  ["blocked", "execute_command", "developer-copilot", "block-shell", "Blocked shell class until a JIT grant is issued"],
  ["blocked", "create_pull_request", "developer-copilot", "block-repo-write", "Blocked repo-write tool for quarantined agent"],
  ["alerted", "run_sql", "finance-rag-agent", "readonly-snowflake", "Audited Snowflake query against read-only role"],
  ["allowed", "post_incident_update", "sre-runbook-agent", "watch-secret-paths", "Allowed messaging tool outside secret path scope"],
  ["blocked", "write_file", "developer-copilot", "block-repo-write", "Blocked workspace write against protected path"],
].map(([action, tool, agent, rule, reason], index) => ({
  entry_id: `audit-${index + 1}`,
  policy_id: index < 2 ? "policy-default-deny" : "policy-rag-readonly",
  policy_name: index < 2 ? gatewayPolicies[0].name : gatewayPolicies[1].name,
  rule_id: rule,
  agent_name: agent,
  tool_name: tool,
  arguments_preview: { redacted: true },
  action_taken: action,
  reason,
  timestamp: CREATED_AT,
}));

function graphResponseWithPagination(data = graph) {
  return {
    ...data,
    pagination: { total: data.nodes.length, offset: 0, limit: data.nodes.length, has_more: false },
  };
}

async function fulfill(route, body, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installRoutes(page) {
  await page.route("**/health", (route) => fulfill(route, { status: "ok" }));
  await page.route("**/v1/auth/me", (route) => fulfill(route, {
    authenticated: true,
    auth_required: false,
    configured_modes: [],
    recommended_ui_mode: "no_auth",
    auth_method: null,
    subject: null,
    role: "admin",
    role_summary: null,
    tenant_id: "default",
    memberships: [],
    request_id: "req-proof-capture",
    trace_id: "trace-proof-capture",
    span_id: "span-proof-capture",
  }));
  await page.route("**/v1/posture/counts", (route) => fulfill(route, {
    critical: 9,
    high: 13,
    medium: 4,
    low: 0,
    total: 26,
    kev: 1,
    compound_issues: 4,
    deployment_mode: "hybrid",
    has_mcp_context: true,
    has_agent_context: true,
    has_local_scan: true,
    has_fleet_ingest: true,
    has_gateway: true,
    has_traces: true,
    scan_count: 3,
    scan_sources: ["local", "fleet-sync", "gateway-runtime"],
  }));
  await page.route("**/v1/posture", (route) => fulfill(route, {
    grade: "D",
    score: 43,
    summary: "26 findings across MCP, identity, runtime policy, and package reachability.",
    dimensions: {
      exploitability: { score: 18, label: "Exploitability", details: "Critical CVE is reachable from repo-write MCP." },
      identity: { score: 34, label: "Identity", details: "JIT reviewer can assume prod AI role." },
      runtime: { score: 61, label: "Runtime", details: "Gateway blocks high-risk tool classes." },
    },
  }));
  await page.route("**/v1/jobs**", (route) => fulfill(route, { jobs: [scanJob()], count: 1, total: 1, limit: 50, offset: 0, has_more: false }));
  await page.route(`**/v1/scan/${SCAN_ID}`, (route) => fulfill(route, scanJob()));
  await page.route(`**/v1/scan/${SCAN_ID}/context-graph**`, (route) => fulfill(route, contextGraph()));
  await page.route("**/v1/graph/snapshots?**", (route) => fulfill(route, [
    { scan_id: SCAN_ID, created_at: CREATED_AT, node_count: graph.nodes.length, edge_count: graph.edges.length, risk_summary: graph.stats.severity_counts },
    { scan_id: PREVIOUS_SCAN_ID, created_at: "2026-06-03T19:00:00Z", node_count: 22, edge_count: 25, risk_summary: { critical: 5, high: 8, medium: 6 } },
  ]));
  await page.route("**/v1/graph/views/fix-first?**", (route) => fulfill(route, fixFirstView()));
  await page.route("**/v1/graph/attack-paths?**", (route) => fulfill(route, graphResponseWithPagination()));
  await page.route("**/v1/graph/diff?**", (route) => fulfill(route, {
    nodes_added: ["sa:jit-review", "role:prod-admin", "policy:gateway-default-deny", "cve:next"],
    nodes_removed: [],
    nodes_changed: ["agent:developer-copilot", "server:github", "cred:github"],
    edges_added: [["sa:jit-review", "role:prod-admin", "assumes"], ["policy:gateway-default-deny", "tool:exec", "manages"]],
    edges_removed: [],
  }));
  await page.route("**/v1/graph/query", (route) => fulfill(route, {
    ...graph,
    roots: ["agent:developer-copilot"],
    direction: "both",
    max_depth: 4,
    max_nodes: 800,
    max_edges: 8000,
    timeout_ms: 2500,
    budget: { nodes: 800, edges: 8000 },
    truncated: false,
    missing_roots: [],
    depth_by_node: Object.fromEntries(graph.nodes.map((item, index) => [item.id, Math.min(4, Math.floor(index / 6))])),
    filters: {},
  }));
  await page.route("**/v1/graph/search?**", (route) => fulfill(route, {
    query: "developer-copilot",
    results: graph.nodes.filter((item) => ["agent:developer-copilot", "server:github", "cve:next", "cred:github"].includes(item.id)),
    pagination: { total: 4, offset: 0, limit: 16, has_more: false },
  }));
  await page.route("**/v1/graph/node/**", async (route) => {
    const url = new URL(route.request().url());
    const parts = url.pathname.split("/");
    const nodeId = decodeURIComponent(parts[parts.length - 1] ?? "");
    const selected = graph.nodes.find((item) => item.id === nodeId) ?? graph.nodes[0];
    await fulfill(route, {
      node: selected,
      edges_out: graph.edges.filter((item) => item.source === selected.id),
      edges_in: graph.edges.filter((item) => item.target === selected.id),
      neighbors: graph.edges.filter((item) => item.source === selected.id || item.target === selected.id).flatMap((item) => [item.source, item.target]).filter((id) => id !== selected.id),
      sources: selected.data_sources,
      impact: { node_id: selected.id, affected_nodes: [], affected_by_type: {}, affected_count: 0, max_depth_reached: 0 },
    });
  });
  await page.route("**/v1/graph?**", (route) => fulfill(route, graphResponseWithPagination()));
  await page.route("**/v1/fleet/stats", (route) => fulfill(route, {
    total: fleetAgents.length,
    by_state: { discovered: 0, pending_review: 1, approved: 2, quarantined: 1, decommissioned: 0 },
    by_environment: { "prod-ai-control-plane": 2, "prod-finance": 1, staging: 1 },
    avg_trust_score: 63,
    low_trust_count: 2,
  }));
  await page.route("**/v1/fleet?**", (route) => fulfill(route, {
    agents: fleetAgents,
    count: fleetAgents.length,
    total: fleetAgents.length,
    limit: 100,
    offset: 0,
    has_more: false,
  }));
  await page.route("**/v1/gateway/policies", (route) => fulfill(route, { policies: gatewayPolicies, count: gatewayPolicies.length }));
  await page.route("**/v1/gateway/stats", (route) => fulfill(route, {
    total_policies: gatewayPolicies.length,
    enforce_count: 1,
    audit_count: 1,
    enabled_count: 2,
    total_rules: 4,
    audit_entries: gatewayAudit.length,
    blocked_count: 3,
    alerted_count: 1,
    policy_runtime: {
      source: "policy-store",
      source_kind: "sqlite",
      enabled_policies: 2,
      rollout_mode: "mixed",
      summary: "Gateway is enforcing shell/repo-write blocks in prod and auditing finance RAG access.",
      total_rules: 4,
      blocking_rules: 2,
      advisory_rules: 2,
      allowlist_rules: 1,
      default_deny_rules: 1,
      read_only_rules: 1,
      secret_path_rules: 1,
      unknown_egress_rules: 1,
      denied_tool_classes: ["shell", "repo_write", "secret_path"],
      blocks_requests: true,
      advisory_only: false,
      default_deny: true,
      protects_secret_paths: true,
      restricts_unknown_egress: true,
    },
    firewall_runtime: {
      total_decisions: 38,
      allow: 24,
      warn: 7,
      deny: 7,
      last_seen_ts: 1780518600,
      top_pairs: [
        { source_agent: "developer-copilot", target_agent: "sre-runbook-agent", allow: 2, warn: 3, deny: 4 },
        { source_agent: "finance-rag-agent", target_agent: "snowflake-rag MCP", allow: 12, warn: 2, deny: 0 },
      ],
      recent: [
        { timestamp: 1780518600, source_agent: "developer-copilot", target_agent: "filesystem MCP", decision: "deny", effective_decision: "deny", matched_rule: { source: "developer-copilot", target: "filesystem MCP", decision: "deny", description: "Block shell class" }, enforcement_mode: "enforce" },
      ],
    },
  }));
  await page.route("**/v1/gateway/audit", (route) => fulfill(route, { entries: gatewayAudit, count: gatewayAudit.length }));
  await page.route("**/v1/gateway/evaluate", (route) => fulfill(route, { allowed: false, reason: "Blocked by default-deny prod MCP runtime / block-shell" }));
}

async function waitForServer(url) {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timed out waiting for ${url}`);
}

function startServerIfNeeded() {
  if (baseUrlFromEnv) return null;
  const child = spawn("npm", ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(PORT)], {
    cwd: UI_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1", NEXT_PUBLIC_API_URL: "" },
  });
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  return child;
}

async function capture(page, urlPath, filename, beforeShot) {
  await page.goto(`${BASE_URL}${urlPath}`);
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(1200);
  if (beforeShot) await beforeShot(page);
  await page.screenshot({ path: path.join(IMAGE_DIR, filename), fullPage: false });
  console.log(`captured ${filename}`);
}

async function main() {
  await fs.mkdir(IMAGE_DIR, { recursive: true });
  const server = startServerIfNeeded();
  try {
    await waitForServer(BASE_URL);
    const browser = await chromium.launch();
    const page = await browser.newPage({ viewport: { width: 1440, height: 980 }, deviceScaleFactor: 1 });
    await installRoutes(page);
    await page.addInitScript(() => {
      window.localStorage.setItem("agent-bom-theme", "dark");
    });

    await capture(page, "/security-graph?capture=1", "security-graph-live.png");
    await capture(page, `/graph?capture=1&scan=${SCAN_ID}`, "lineage-graph-live.png", async (lineagePage) => {
      await lineagePage.getByText("View controls").first().click();
      await lineagePage.getByRole("button", { name: "Expanded topology" }).click();
      await lineagePage.waitForTimeout(800);
      await lineagePage.locator(".react-flow").first().scrollIntoViewIfNeeded();
      await lineagePage.locator(".react-flow__controls-fitview").first().click();
      await lineagePage.waitForTimeout(500);
    });
    await capture(page, "/context?capture=1", "context-map-live.png");
    await capture(page, "/fleet?capture=1", "fleet-state-live.png", async (fleetPage) => {
      await fleetPage.getByText("developer-copilot").first().click();
      await fleetPage.waitForTimeout(500);
    });
    await capture(page, "/gateway?capture=1", "gateway-policies-live.png", async (gatewayPage) => {
      await gatewayPage.getByText("Default-deny prod MCP runtime").first().click();
      await gatewayPage.waitForTimeout(500);
    });
    await browser.close();
  } finally {
    if (server) {
      server.kill("SIGTERM");
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
