#!/usr/bin/env node
import { chromium } from "@playwright/test";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const REPO_ROOT = path.resolve(UI_ROOT, "..");
const IMAGE_DIR = path.join(REPO_ROOT, "docs", "images");
const SCREENSHOT_MANIFEST = path.join(IMAGE_DIR, "product-screenshots.json");
const UI_PACKAGE = JSON.parse(await fs.readFile(path.join(UI_ROOT, "package.json"), "utf8"));
const RELEASE_VERSION = UI_PACKAGE.version;
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
    node("container:agent-gateway", "container", "agent-gateway:0.91.0", "high", 7.6, { image: "agent-bom/gateway:0.91.0" }),
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

function vuln(id, severity, cvss, epss, fixedVersion, isKev = false) {
  return {
    id,
    severity,
    summary: `${id} reachable from an MCP-backed runtime path`,
    description: `${id} is present in a package reachable from agent tooling.`,
    references: [`https://example.invalid/advisory/${id}`],
    advisory_sources: ["nvd", "osv"],
    cvss_score: cvss,
    epss_score: epss,
    is_kev: isKev,
    cisa_kev: isKev,
    fixed_version: fixedVersion,
    confidence: 0.98,
  };
}

const DEMO_AGENT_SPECS = [
  { name: "data-pipeline-agent", agent_type: "etl", owner: "data-platform", environment: "prod-analytics", server: "warehouse MCP", pkg: "pandas", version: "2.2.3", ecosystem: "pypi", cve: ["CVE-2026-44102", "high", 7.9, 0.44, "2.2.4"] },
  { name: "customer-support-bot", agent_type: "support", owner: "cx-ops", environment: "prod-support", server: "zendesk MCP", pkg: "requests", version: "2.32.3", ecosystem: "pypi", cve: ["CVE-2026-11880", "medium", 6.4, 0.21, "2.32.4"] },
  { name: "legal-review-agent", agent_type: "review", owner: "legal", environment: "prod-legal", server: "docusign MCP", pkg: "cryptography", version: "43.0.3", ecosystem: "pypi", cve: ["CVE-2026-55210", "high", 8.2, 0.36, "44.0.1"] },
  { name: "hr-onboarding-agent", agent_type: "hr", owner: "people-ops", environment: "prod-hr", server: "workday MCP", pkg: "pillow", version: "11.1.0", ecosystem: "pypi", cve: null },
  { name: "marketing-copilot", agent_type: "marketing", owner: "growth", environment: "staging", server: "hubspot MCP", pkg: "react", version: "19.0.0", ecosystem: "npm", cve: ["CVE-2026-33011", "high", 8.0, 0.39, "19.0.1"] },
  { name: "incident-commander", agent_type: "runbook", owner: "sre", environment: "prod-ai-control-plane", server: "pagerduty MCP", pkg: "aiohttp", version: "3.11.12", ecosystem: "pypi", cve: ["CVE-2026-77881", "critical", 9.1, 0.67, "3.11.14"] },
  { name: "platform-ops-agent", agent_type: "ops", owner: "platform", environment: "prod-ai-control-plane", server: "kubernetes MCP", pkg: "kubernetes", version: "32.0.0", ecosystem: "pypi", cve: ["CVE-2026-90221", "high", 7.6, 0.33, "32.0.2"] },
  { name: "ml-training-agent", agent_type: "ml", owner: "ml-platform", environment: "prod-ml", server: "wandb MCP", pkg: "torch", version: "2.6.0", ecosystem: "pypi", cve: ["CVE-2026-66110", "high", 8.4, 0.48, "2.6.1"] },
  { name: "code-review-bot", agent_type: "ide", owner: "engineering", environment: "prod-ai-control-plane", server: "gitlab MCP", pkg: "eslint", version: "9.21.0", ecosystem: "npm", cve: null },
  { name: "compliance-auditor", agent_type: "audit", owner: "grc", environment: "prod-grc", server: "grc MCP", pkg: "pydantic", version: "2.10.6", ecosystem: "pypi", cve: ["CVE-2026-22001", "medium", 5.9, 0.18, "2.10.7"] },
  { name: "vendor-risk-agent", agent_type: "risk", owner: "security", environment: "staging", server: "vendor MCP", pkg: "starlette", version: "0.45.3", ecosystem: "pypi", cve: ["CVE-2026-44190", "high", 7.8, 0.29, "0.46.0"] },
  { name: "research-assistant", agent_type: "rag", owner: "research", environment: "staging", server: "arxiv MCP", pkg: "transformers", version: "4.49.0", ecosystem: "pypi", cve: ["CVE-2026-99120", "medium", 6.1, 0.16, "4.49.2"] },
  { name: "sales-enablement-bot", agent_type: "sales", owner: "revenue", environment: "prod-sales", server: "salesforce MCP", pkg: "simple-salesforce", version: "1.12.6", ecosystem: "pypi", cve: null },
  { name: "devops-release-agent", agent_type: "release", owner: "devops", environment: "prod-ai-control-plane", server: "argocd MCP", pkg: "helm", version: "3.17.0", ecosystem: "pypi", cve: ["CVE-2026-55001", "high", 7.5, 0.31, "3.17.1"] },
  { name: "shadow-copilot", agent_type: "shadow", owner: "unknown", environment: "unmanaged", server: "openai MCP", pkg: "openai", version: "1.66.3", ecosystem: "pypi", cve: ["CVE-2026-88001", "critical", 9.0, 0.71, "1.66.5"] },
];

function demoScanAgent(spec) {
  const vulnerabilities = spec.cve
    ? [vuln(spec.cve[0], spec.cve[1], spec.cve[2], spec.cve[3], spec.cve[4], spec.cve[1] === "critical" && spec.cve[2] >= 9)]
    : [];
  return {
    name: spec.name,
    agent_type: spec.agent_type,
    owner: spec.owner,
    environment: spec.environment,
    tags: ["simulated", spec.environment.startsWith("prod") ? "prod" : "staging"],
    mcp_servers: [
      {
        name: spec.server,
        transport: "sse",
        config_path: `/workspace/${spec.name}/mcp.json`,
        has_credentials: spec.name !== "code-review-bot",
        credential_env_vars: spec.name !== "code-review-bot" ? [`${spec.name.toUpperCase().replace(/-/g, "_")}_TOKEN`] : [],
        tools: [{ name: "query" }, { name: "read_context" }],
        packages: [
          {
            name: spec.pkg,
            version: spec.version,
            ecosystem: spec.ecosystem,
            purl: `pkg:${spec.ecosystem}/${spec.pkg}@${spec.version}`,
            vulnerabilities,
          },
        ],
      },
    ],
  };
}

function buildBlastRadius() {
  const entries = [
    {
      vulnerability_id: "CVE-2026-21441",
      severity: "critical",
      package: "next",
      ecosystem: "npm",
      affected_agents: ["developer-copilot"],
      affected_servers: ["github-enterprise MCP"],
      exposed_credentials: ["GITHUB_FINE_GRAINED_TOKEN"],
      reachable_tools: ["create_pull_request"],
      blast_score: 98,
      risk_score: 9.8,
      cvss_score: 9.8,
      epss_score: 0.82,
      is_kev: true,
      cisa_kev: true,
      fixed_version: "16.2.7",
    },
    {
      vulnerability_id: "CVE-2026-32597",
      severity: "high",
      package: "urllib3",
      ecosystem: "pypi",
      affected_agents: ["sre-runbook-agent", "developer-copilot"],
      affected_servers: ["filesystem MCP"],
      exposed_credentials: ["AWS_ROLE_SESSION"],
      reachable_tools: ["execute_command"],
      blast_score: 89,
      risk_score: 8.9,
      cvss_score: 8.8,
      epss_score: 0.51,
      fixed_version: "2.5.1",
    },
    {
      vulnerability_id: "CVE-2026-0994",
      severity: "high",
      package: "protobuf",
      ecosystem: "pypi",
      affected_agents: ["finance-rag-agent"],
      affected_servers: ["snowflake-rag MCP"],
      exposed_credentials: ["SNOWFLAKE_PROD_KEY"],
      reachable_tools: ["run_sql"],
      blast_score: 81,
      risk_score: 8.1,
      cvss_score: 8.1,
      epss_score: 0.38,
      fixed_version: "6.33.4",
    },
    {
      vulnerability_id: "CVE-2026-77881",
      severity: "critical",
      package: "aiohttp",
      ecosystem: "pypi",
      affected_agents: ["incident-commander"],
      affected_servers: ["pagerduty MCP"],
      exposed_credentials: ["INCIDENT_COMMANDER_TOKEN"],
      reachable_tools: ["query"],
      blast_score: 91,
      risk_score: 9.1,
      cvss_score: 9.1,
      epss_score: 0.67,
      fixed_version: "3.11.14",
    },
    {
      vulnerability_id: "CVE-2026-88001",
      severity: "critical",
      package: "openai",
      ecosystem: "pypi",
      affected_agents: ["shadow-copilot"],
      affected_servers: ["openai MCP"],
      exposed_credentials: ["SHADOW_COPILOT_TOKEN"],
      reachable_tools: ["query"],
      blast_score: 90,
      risk_score: 9.0,
      cvss_score: 9.0,
      epss_score: 0.71,
      fixed_version: "1.66.5",
    },
  ];
  for (const spec of DEMO_AGENT_SPECS) {
    if (!spec.cve) continue;
    const [id, severity, cvss, epss, fixedVersion] = spec.cve;
    entries.push({
      vulnerability_id: id,
      severity,
      package: spec.pkg,
      ecosystem: spec.ecosystem,
      affected_agents: [spec.name],
      affected_servers: [spec.server],
      exposed_credentials: [`${spec.name.toUpperCase().replace(/-/g, "_")}_TOKEN`],
      reachable_tools: ["query"],
      blast_score: Math.round(cvss * 10),
      risk_score: cvss,
      cvss_score: cvss,
      epss_score: epss,
      is_kev: severity === "critical" && cvss >= 9,
      cisa_kev: severity === "critical" && cvss >= 9,
      fixed_version: fixedVersion,
    });
  }
  return entries;
}

function buildFindings() {
  return buildBlastRadius().map((item, index) => ({
    id: `finding-${index + 1}`,
    canonical_id: item.vulnerability_id,
    finding_type: "vulnerability",
    source: "nvd",
    severity: item.severity,
    effective_severity: item.severity,
    title: `Reachable ${item.severity} package on ${item.affected_servers?.[0] ?? "MCP path"}`,
    description: `${item.vulnerability_id} is reachable from ${item.affected_agents.join(", ")} through simulated MCP tooling.`,
    cve_id: item.vulnerability_id,
    cvss_score: item.cvss_score,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    attack_vector: "network",
    epss_score: item.epss_score,
    is_kev: Boolean(item.is_kev),
    fixed_version: item.fixed_version,
    remediation_guidance: `Upgrade ${item.package} to ${item.fixed_version} and rerun the graph scan.`,
    compliance_tags: ["OWASP-LLM05", "ATLAS-AML.T0051"],
    risk_score: item.risk_score,
    impact_category: item.severity === "critical" ? "RCE" : "Exposure",
    affected_servers: item.affected_servers ?? [],
    affected_agents: item.affected_agents,
    exposed_credentials: item.exposed_credentials,
    exposed_tools: item.reachable_tools,
    scan_id: SCAN_ID,
    scan_sources: ["demo-scan"],
  }));
}

function scanSummary(agentCount) {
  return {
    total_agents: agentCount,
    total_servers: 22,
    total_packages: 148,
    total_vulnerabilities: 26,
    critical_findings: 9,
    high_findings: 13,
    medium_findings: 4,
    low_findings: 0,
  };
}

function scanAgents() {
  return [
    {
      name: "developer-copilot",
      agent_type: "ide",
      owner: "platform-security",
      environment: "prod-ai-control-plane",
      tags: ["prod", "repo-write", "jit-review"],
      mcp_servers: [
        {
          name: "github-enterprise MCP",
          transport: "sse",
          config_path: "/workspace/prod/.cursor/mcp.json",
          has_credentials: true,
          credential_env_vars: ["GITHUB_FINE_GRAINED_TOKEN"],
          tools: [{ name: "create_pull_request" }, { name: "read_repository" }],
          packages: [
            {
              name: "next",
              version: "16.2.6",
              ecosystem: "npm",
              purl: "pkg:npm/next@16.2.6",
              vulnerabilities: [vuln("CVE-2026-21441", "critical", 9.8, 0.82, "16.2.7", true)],
            },
          ],
        },
        {
          name: "filesystem MCP",
          transport: "stdio",
          config_path: "/workspace/prod/.cursor/mcp.json",
          has_credentials: true,
          credential_env_vars: ["AWS_ROLE_SESSION"],
          tools: [{ name: "execute_command" }, { name: "read_file" }],
          packages: [
            {
              name: "urllib3",
              version: "2.4.0",
              ecosystem: "pypi",
              purl: "pkg:pypi/urllib3@2.4.0",
              vulnerabilities: [vuln("CVE-2026-32597", "high", 8.8, 0.51, "2.5.1")],
            },
          ],
        },
      ],
    },
    {
      name: "sre-runbook-agent",
      agent_type: "runbook",
      owner: "sre",
      environment: "prod-ai-control-plane",
      tags: ["prod", "command-tooling"],
      mcp_servers: [
        {
          name: "filesystem MCP",
          transport: "stdio",
          config_path: "/ops/runbooks/mcp.json",
          has_credentials: true,
          credential_env_vars: ["AWS_ROLE_SESSION"],
          tools: [{ name: "execute_command" }, { name: "read_file" }],
          packages: [
            {
              name: "urllib3",
              version: "2.4.0",
              ecosystem: "pypi",
              purl: "pkg:pypi/urllib3@2.4.0",
              vulnerabilities: [vuln("CVE-2026-32597", "high", 8.8, 0.51, "2.5.1")],
            },
          ],
        },
      ],
    },
    {
      name: "finance-rag-agent",
      agent_type: "rag",
      owner: "finance-data",
      environment: "prod-finance",
      tags: ["prod", "rag", "confidential-data"],
      mcp_servers: [
        {
          name: "snowflake-rag MCP",
          transport: "sse",
          config_path: "/finance/rag/mcp.json",
          has_credentials: true,
          credential_env_vars: ["SNOWFLAKE_PROD_KEY"],
          tools: [{ name: "run_sql" }, { name: "read_lineage" }],
          packages: [
            {
              name: "protobuf",
              version: "6.33.2",
              ecosystem: "pypi",
              purl: "pkg:pypi/protobuf@6.33.2",
              vulnerabilities: [vuln("CVE-2026-0994", "high", 8.1, 0.38, "6.33.4")],
            },
            {
              name: "langchain",
              version: "0.3.21",
              ecosystem: "pypi",
              purl: "pkg:pypi/langchain@0.3.21",
              vulnerabilities: [],
            },
          ],
        },
      ],
    },
    ...DEMO_AGENT_SPECS.map(demoScanAgent),
  ];
}

function scanJob() {
  const agents = scanAgents();
  const remediationPlan = [
    {
      package: "next",
      ecosystem: "npm",
      current_version: "16.2.6",
      fixed_version: "16.2.7",
      severity: "critical",
      is_kev: true,
      impact_score: 9.8,
      priority: 1,
      action: "upgrade",
      reason: "Critical reachable package on the highest-risk repo-write MCP path.",
      command: "npm install next@16.2.7",
      verify_command: "agent-bom scan --fail-on-severity high",
      vulnerabilities: ["CVE-2026-21441"],
      affected_agents: ["developer-copilot"],
      agents_pct: 33,
      exposed_credentials: ["GITHUB_FINE_GRAINED_TOKEN"],
      credentials_pct: 33,
      reachable_tools: ["create_pull_request"],
      tools_pct: 25,
      owasp_tags: ["LLM05", "LLM06"],
      atlas_tags: ["AML.T0051"],
      references: ["https://example.invalid/advisory/CVE-2026-21441"],
      risk_narrative: "Patch the package first because the affected server exposes repo-write tooling and a credential reference.",
    },
    {
      package: "urllib3",
      ecosystem: "pypi",
      current_version: "2.4.0",
      fixed_version: "2.5.1",
      severity: "high",
      is_kev: false,
      impact_score: 8.9,
      priority: 2,
      action: "upgrade",
      reason: "Runbook agent reaches command tooling through the vulnerable dependency path.",
      command: "python -m pip install urllib3==2.5.1",
      verify_command: "agent-bom scan --fail-on-severity high",
      vulnerabilities: ["CVE-2026-32597"],
      affected_agents: ["sre-runbook-agent"],
      agents_pct: 33,
      exposed_credentials: ["AWS_ROLE_SESSION"],
      credentials_pct: 33,
      reachable_tools: ["execute_command"],
      tools_pct: 25,
      owasp_tags: ["LLM06"],
      atlas_tags: ["AML.T0054"],
      references: ["https://example.invalid/advisory/CVE-2026-32597"],
      risk_narrative: "Prioritize after the KEV path because it reaches shell-class tooling.",
    },
  ];
  return {
    job_id: SCAN_ID,
    status: "done",
    created_at: CREATED_AT,
    request: {},
    progress: [],
    summary: scanSummary(agents.length),
    result: {
      agents,
      blast_radius: buildBlastRadius(),
      remediation_plan: remediationPlan,
      scan_sources: ["demo-scan", "fleet-sync", "gateway-runtime"],
    },
  };
}

function fleetAgentFromScan(agent, index) {
  const lifecycleStates = ["quarantined", "pending_review", "approved", "approved", "discovered"];
  const lifecycle_state = agent.name === "developer-copilot"
    ? "quarantined"
    : agent.name === "sre-runbook-agent"
      ? "pending_review"
      : agent.name === "shadow-copilot"
        ? "quarantined"
        : lifecycleStates[index % lifecycleStates.length];
  const vulnCount = agent.mcp_servers.flatMap((srv) => srv.packages).flatMap((pkg) => pkg.vulnerabilities ?? []).length;
  return {
    agent_id: `agent:${agent.name}`,
    name: agent.name,
    agent_type: agent.agent_type,
    config_path: agent.mcp_servers[0]?.config_path ?? `/workspace/${agent.name}/mcp.json`,
    lifecycle_state,
    owner: agent.owner,
    environment: agent.environment,
    tags: agent.tags,
    trust_score: Math.max(28, 92 - vulnCount * 6 - (lifecycle_state === "quarantined" ? 18 : 0)),
    trust_factors: { simulated: 1, findings: vulnCount },
    server_count: agent.mcp_servers.length,
    package_count: agent.mcp_servers.reduce((sum, srv) => sum + srv.packages.length, 0) + 8,
    credential_count: agent.mcp_servers.filter((srv) => srv.has_credentials).length,
    vuln_count: vulnCount,
    last_discovery: CREATED_AT,
    last_scan: CREATED_AT,
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
    notes: "Simulated fleet record for docs proof.",
  };
}

const fleetAgents = scanAgents().map(fleetAgentFromScan);

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

function overviewResponse() {
  const domain = (label, href, metric, metricLabel, status, detail = {}) => ({
    label,
    href,
    metric,
    metric_label: metricLabel,
    status,
    detail,
  });
  return {
    schema_version: "overview.v1",
    tenant_id: "default",
    posture: {
      grade: "D",
      score: 43,
      summary: "Reachable agent, MCP, credential, and package evidence is normalized into one operator queue.",
    },
    headline: {
      critical: 9,
      high: 13,
      critical_high: 22,
      kev: 1,
      credential_exposed: 3,
      scans: 3,
      latest_scan_at: CREATED_AT,
    },
    domains: {
      cloud: domain("Cloud", "/connections", 4, "connected surfaces", "warn", { mode: "read-only" }),
      runtime: domain("Runtime", "/gateway", 247, "blocked today", "critical", { mode: "enforce" }),
      cost: domain("Cost", "/cost", 18, "agent budgets", "ok", { forecast: "stable" }),
      identity: domain("Identity", "/identity", 3, "keys rotated", "warn", { scim: "enabled" }),
      ops: domain("Ops", "/jobs", 3, "completed scans", "ok", { scheduler: "enabled" }),
    },
    top_risks: [
      {
        vulnerability_id: "CVE-2026-21441",
        package: "next",
        severity: "critical",
        risk_score: 9.8,
        is_kev: true,
        cvss_score: 9.8,
        epss_score: 0.82,
        affected_agents: ["developer-copilot"],
      },
    ],
  };
}

function authPolicyResponse() {
  const quota = (limit, current, status = "ok") => ({
    limit,
    default_limit: limit,
    override_limit: null,
    current,
    remaining: Math.max(0, limit - current),
    enforced: true,
    source: "tenant_default",
    utilization_pct: Math.round((current / limit) * 100),
    status,
    recommended_action: status === "near_limit" ? "raise quota or reduce schedule cadence" : "no action",
  });
  const rotation = (status, message) => ({
    status,
    configured: true,
    required: true,
    source: "environment",
    persists_across_restart: true,
    rotation_tracking_supported: true,
    rotation_status: "ok",
    rotation_method: "operator_rotated",
    rotation_days: 30,
    max_age_days: 90,
    last_rotated: CREATED_AT,
    age_days: 0,
    rotation_message: "Rotation metadata is present and current.",
    message,
  });
  return {
    api_key: {
      default_ttl_seconds: 86400,
      max_ttl_seconds: 604800,
      default_overlap_seconds: 900,
      max_overlap_seconds: 3600,
      rotation_policy: "overlap_then_revoke",
      rotation_endpoint: "/v1/auth/keys/{key_id}/rotate",
    },
    rate_limit_key: {
      status: "ok",
      last_rotated: CREATED_AT,
      age_days: 0,
      rotation_days: 30,
      max_age_days: 90,
      message: "Rate-limit identity is bound to authenticated tenant and caller.",
      fallback_source: null,
    },
    audit_hmac: { status: "configured", configured: true, key_id_configured: true, rotation_tracking_supported: true },
    ui: {
      recommended_mode: "trusted_proxy",
      configured_modes: ["api_key", "trusted_proxy", "oidc_bearer"],
      browser_session: "signed_http_only_cookie",
      session_storage_fallback: "disabled",
      credentials_mode: "include",
      trusted_proxy_headers: ["X-Agent-Bom-Role", "X-Agent-Bom-Tenant-ID"],
      message: "Browser sessions are bound to trusted upstream identity and CSRF-protected cookies.",
    },
    rate_limit_runtime: {
      backend: "postgres",
      postgres_configured: true,
      configured_api_replicas: 2,
      shared_required: true,
      shared_across_replicas: true,
      fail_closed: true,
      message: "Global and per-tenant ceilings are enforced before expensive work starts.",
    },
    secret_integrity: {
      audit_hmac: rotation("configured", "Audit HMAC signing is configured and persists across restarts."),
      compliance_signing: {
        ...rotation("configured", "Compliance bundles are signed for auditor verification."),
        algorithm: "ed25519",
        mode: "detached",
        key_id: "capture-key",
        public_key_endpoint: "/v1/compliance/public-key",
        auditor_distributable: true,
        uses_audit_hmac_secret: false,
      },
    },
    tenant_quotas: { active_scan_jobs: 4, retained_scan_jobs: 200, fleet_agents: 500, schedules: 25 },
    tenant_quota_runtime: {
      source: "tenant_defaults",
      per_tenant_overrides: true,
      active_override: false,
      override_endpoint: "/v1/auth/quota",
      message: "Quotas protect scan workers, graph storage, and hosted POC capacity.",
      overrides: {},
      usage: {
        active_scan_jobs: quota(4, 1),
        retained_scan_jobs: quota(200, 83),
        fleet_agents: quota(500, fleetAgents.length),
        schedules: quota(25, 3),
      },
    },
    identity_provisioning: {
      oidc: {
        supported: true,
        configured: true,
        mode: "trusted_proxy",
        issuer_hosts: ["idp.example.invalid"],
        provider_count: 1,
        audience_configured: true,
        role_claim: "agent_bom_role",
        tenant_claim: "agent_bom_tenant",
        require_role_claim: true,
        require_tenant_claim: true,
        allow_default_tenant: false,
        required_nonce: true,
        message: "OIDC sessions bind role and tenant server-side.",
      },
      saml: {
        supported: true,
        configured: true,
        metadata_endpoint: "/v1/auth/saml/metadata",
        acs_path: "/v1/auth/saml/acs",
        idp_host: "idp.example.invalid",
        role_attribute: "agent_bom_role",
        tenant_attribute: "agent_bom_tenant",
        require_role_attribute: true,
        require_tenant_attribute: true,
        session_ttl_seconds: 3600,
        message: "SAML browser sessions expire quickly and stay tenant-bound.",
      },
      scim: {
        supported: true,
        configured: true,
        status: "configured",
        base_path: "/v1/scim/v2",
        token_configured: true,
        external_id_attribute: "externalId",
        role_attribute: "agent_bom_role",
        default_role: "viewer",
        role_values: ["admin", "analyst", "viewer", "external"],
        tenant_attribute: "agent_bom_tenant",
        tenant_assignment: { source: "server_bound_tenant", payload_tenant_attributes_ignored: true },
        provisioning_authority: "scim_lifecycle_store",
        auth_authority: "api_key_oidc_saml_trusted_proxy_with_scim_role_overlay",
        runtime_auth_enforced: true,
        deprovisioning_boundary: "SCIM deactivate/delete updates provisioned lifecycle state.",
        groups_required: false,
        message: "SCIM roles overlay authenticated users inside the server-bound tenant.",
      },
      session_revocation: {
        service_keys: "API key revocation takes effect at the control-plane auth layer.",
        session_api_key: "Browser fallback keys disappear when the local session is cleared.",
        browser_sessions: "OIDC and reverse-proxy sessions terminate at the upstream identity provider.",
      },
    },
    data_access_boundaries: {
      default_posture: {
        self_hosted_first: true,
        mandatory_hosted_control_plane: false,
        hidden_telemetry: false,
        default_network_mode: "read_only_pull",
        credential_values_stored: false,
        credential_values_transmitted: false,
        credential_values_validated_by_default: false,
        support_access_default: "customer_controlled",
      },
      modes: [
        { mode: "local_cli", reads: ["repo", "image", "sbom"], evidence: ["sarif", "json"], does_not_read: ["cloud_secret_values"] },
        { mode: "self_hosted", reads: ["cloud_metadata", "snowflake_account_usage"], controls: ["tenant_scope", "rbac", "audit"] },
        { mode: "gateway", reads: ["tool_call_metadata"], controls: ["scope", "dlp", "deny"] },
      ],
      network_boundaries: {
        telemetry: "disabled_by_default",
        vulnerability_enrichment: "bounded_http_to_public_advisory_sources",
        cloud_provider_api_calls: "read_only",
        outbound_exports: "operator_configured",
        proxy_gateway_egress: "policy_controlled",
        disable_controls: ["AGENT_BOM_OFFLINE", "AGENT_BOM_DISABLE_NETWORK"],
      },
      storage_boundaries: {
        local_default: "local_file",
        control_plane_default: "tenant_scoped_database",
        secret_values: "never_stored",
        secret_previews: "redacted_only",
        raw_artifact_exports: "operator_requested",
        support_bundle_default: "redacted",
      },
      auth_boundaries: {
        api: ["api_key", "oidc", "saml", "trusted_proxy"],
        authorization: ["server_bound_tenant", "rbac_role", "capability_scope"],
        scim: {
          provisioning_authority: "scim_lifecycle_store",
          runtime_auth_overlay: "upstream_authenticated",
          tenant_source: "server_bound_tenant",
          payload_tenant_attributes_ignored: true,
        },
        does_not_do: ["password_auth", "plaintext_key_storage", "caller_asserted_tenant"],
      },
      deployment_boundaries: { hosted_poc: ["manual_invites", "quotas", "monitoring"], self_hosted: ["customer_vpc", "customer_database"] },
      extension_boundaries: {
        connectors: {
          default_posture: "read_only",
          credential_scope: "per_tenant_connection",
          does_not_do: ["read_secret_values", "write_cloud_resources"],
          stronger_actions_require: ["operator_approval", "explicit_flag"],
        },
        plugins_and_skills: {
          default_posture: "disabled_until_configured",
          execution_boundary: "operator_controlled",
          does_not_do: ["ambient_execution"],
          controls: ["allowlist", "audit", "timeouts"],
        },
        roles: {
          viewer: ["read"],
          analyst: ["read", "triage"],
          admin: ["read", "write", "configure"],
          principle: "least_privilege_by_default",
        },
      },
      posture_vocabulary: {
        capability_flags: ["cloud", "mcp", "gateway"],
        enforcement_flags: ["fail_closed", "quarantine"],
        intentional_boundary_flags: ["read_only", "no_secret_values"],
      },
      operator_controls: {
        scope_preview: "Scans default to the requested path or connected account.",
        inventory_only: "AGENT_BOM_INVENTORY_ONLY",
        project_scope: "--project",
        config_scope: "--config",
        disable_vulnerability_network: "AGENT_BOM_DISABLE_VULN_LOOKUP",
        disable_scan_network_and_vuln_lookup: "AGENT_BOM_OFFLINE",
        disable_skill_scan: "AGENT_BOM_DISABLE_SKILL_SCAN",
        isolate_skill_scan: "AGENT_BOM_ISOLATE_SKILL_SCAN",
        api_access_control: ["rbac", "tenant", "csrf"],
        optional_exports: ["sarif", "sbom", "json", "compliance_bundle"],
      },
      credential_evidence: {
        config_env_vars: "names_only",
        project_secret_scan: "redacted",
        stores_matched_value: false,
        stores_matched_prefix: false,
        validates_live_secret: false,
      },
      redacted_evidence_context: {
        allowed_context: ["resource_id", "env_var_name", "service_name"],
        never_show: ["secret_value", "token", "private_key"],
        display_model: "redacted_summary",
      },
    },
  };
}

function auditEntries() {
  return [
    ["scan.completed", "api", "scan/" + SCAN_ID, { findings: 26, graph_nodes: graph.nodes.length }],
    ["gateway.policy.denied", "gateway", "tool/execute_command", { agent: "developer-copilot", rule: "block-shell" }],
    ["agent_identity.rotated", "api", "identity/id_89c1a6f406bd7189", { tenant: "default" }],
    ["agent_identity.revoked", "api", "identity/id_89c1a6f406bd7189", { tenant: "default" }],
    ["compliance.bundle.signed", "api", "compliance/soc2", { signer: "capture-key" }],
  ].map(([action, actor, resource, details], index) => ({
    entry_id: `entry-${index + 1}`,
    timestamp: CREATED_AT,
    action,
    actor,
    resource,
    details,
    hmac_signature: "verified-demo-signature",
  }));
}

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
  await page.route("**/version", (route) => fulfill(route, { version: "0.91.0", name: "agent-bom" }));
  await page.route("**/v1/auth/me", (route) => fulfill(route, {
    authenticated: true,
    auth_required: false,
    configured_modes: [],
    recommended_ui_mode: "no_auth",
    auth_method: null,
    subject: null,
    role: "admin",
    role_summary: {
      role: "admin",
      ui_role: "admin",
      display_name: "Admin",
      capabilities: ["keys.manage", "audit.read", "scan.write", "gateway.write"],
    },
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
    has_mesh: true,
    has_gateway: true,
    has_traces: true,
    scan_count: 3,
    scan_sources: ["demo-scan", "local", "fleet-sync", "gateway-runtime"],
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
  await page.route("**/v1/overview", (route) => fulfill(route, overviewResponse()));
  await page.route("**/v1/agents", (route) => fulfill(route, {
    agents: scanJob().result.agents,
    count: scanJob().result.agents.length,
    warnings: [],
  }));
  await page.route((url) => {
    try {
      return new URL(url).pathname === "/v1/jobs";
    } catch {
      return false;
    }
  }, (route) => {
    const job = scanJob();
    return fulfill(route, {
      jobs: [{ ...job, summary: job.summary }],
      count: 1,
      total: 1,
      limit: 50,
      offset: 0,
      has_more: false,
    });
  });
  await page.route((url) => {
    try {
      return new URL(url).pathname === `/v1/scan/${SCAN_ID}/context-graph`;
    } catch {
      return false;
    }
  }, (route) => fulfill(route, contextGraph()));
  await page.route((url) => {
    try {
      return new URL(url).pathname === `/v1/scan/${SCAN_ID}`;
    } catch {
      return false;
    }
  }, (route) => fulfill(route, scanJob()));
  await page.route("**/v1/graph/snapshots?**", (route) => fulfill(route, [
    { scan_id: SCAN_ID, created_at: CREATED_AT, node_count: graph.nodes.length, edge_count: graph.edges.length, risk_summary: graph.stats.severity_counts },
    { scan_id: PREVIOUS_SCAN_ID, created_at: "2026-06-03T19:00:00Z", node_count: 22, edge_count: 25, risk_summary: { critical: 5, high: 8, medium: 6 } },
  ]));
  await page.route("**/v1/graph/views/fix-first?**", (route) => fulfill(route, fixFirstView()));
  await page.route("**/v1/graph/rollup?**", (route) => fulfill(route, {
    scan_id: SCAN_ID,
    tenant_id: "default",
    created_at: CREATED_AT,
    mode: "rollup",
    filters: { min_severity: "high" },
    top_level: graph.nodes.slice(0, 6).map((node) => ({
      id: node.id,
      label: node.label,
      entity_type: node.entity_type,
      severity: node.severity,
      child_count: 3,
      risk_score: node.risk_score,
      rollup_has_children: true,
    })),
    summary: {
      total_nodes: graph.nodes.length,
      total_edges: graph.edges.length,
      container_count: 6,
      severity_counts: graph.stats.severity_counts,
    },
  }));
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
  await page.route("**/v1/findings?**", (route) => {
    const findings = buildFindings();
    return fulfill(route, {
      schema_version: "findings.v1",
      findings,
      count: findings.length,
      total: findings.length,
      limit: 50,
      offset: 0,
      sort: "risk",
      scan_id: SCAN_ID,
      warnings: [],
    });
  });
  await page.route("**/v1/fleet/stats", (route) => fulfill(route, {
    total: fleetAgents.length,
    by_state: fleetAgents.reduce((acc, item) => {
      acc[item.lifecycle_state] = (acc[item.lifecycle_state] ?? 0) + 1;
      return acc;
    }, {}),
    by_environment: fleetAgents.reduce((acc, item) => {
      acc[item.environment] = (acc[item.environment] ?? 0) + 1;
      return acc;
    }, {}),
    avg_trust_score: Math.round(fleetAgents.reduce((sum, item) => sum + item.trust_score, 0) / fleetAgents.length),
    low_trust_count: fleetAgents.filter((item) => item.trust_score < 60).length,
  }));
  await page.route("**/v1/fleet?**", (route) => fulfill(route, {
    agents: fleetAgents,
    count: fleetAgents.length,
    total: fleetAgents.length,
    limit: 100,
    offset: 0,
    has_more: false,
  }));
  await page.route("**/v1/auth/policy", (route) => fulfill(route, authPolicyResponse()));
  await page.route("**/v1/auth/keys", (route) => fulfill(route, {
    keys: [
      {
        key_id: "key_demo_admin",
        key_prefix: "abom_live_demo",
        name: "hosted-demo-admin",
        role: "admin",
        created_at: CREATED_AT,
        expires_at: "2026-07-03T20:30:00Z",
        scopes: ["admin", "scan:write", "gateway:write"],
        tenant_id: "default",
        revoked_at: null,
        rotation_overlap_until: null,
        replacement_key_id: null,
        state: "active",
        overlap_seconds_remaining: null,
      },
    ],
  }));
  // Register the broad audit route before the specific integrity route.
  await page.route("**/v1/audit?**", (route) => {
    const entries = auditEntries();
    return fulfill(route, { entries, total: entries.length });
  });
  await page.route("**/v1/audit/integrity?**", (route) => fulfill(route, {
    verified: 78,
    tampered: 0,
    checked: 78,
  }));
  await page.route("**/v1/gateway/policies", (route) => fulfill(route, { policies: gatewayPolicies, count: gatewayPolicies.length }));
  // Register the broad feed route first so the more specific feed/kpis route
  // below takes precedence — Playwright matches the most recently registered
  // route, and `feed**` would otherwise also intercept the `/feed/kpis` request
  // and return the events payload to the KPI fetch.
  await page.route("**/v1/gateway/feed**", (route) => fulfill(route, {
    schema_version: "gateway.feed.v1",
    tenant_id: "tenant-alpha",
    generated_at: CREATED_AT,
    count: 4,
    events: [
      { ts: CREATED_AT, agent: "developer-copilot", action_type: "tool_call_blocked", target: "github.repo-write", detail: "Repo-write blocked by default-deny prod policy", tenant: "tenant-alpha", shadow: false, source: "gateway" },
      { ts: CREATED_AT, agent: "finance-rag-agent", action_type: "data_filter_applied", target: "snowflake.query", detail: "Resume data masked", tenant: "tenant-alpha", shadow: false, source: "gateway" },
      { ts: CREATED_AT, agent: "sre-runbook-agent", action_type: "tool_call_authorized", target: "slack.post", detail: "Tool call authorized", tenant: "tenant-alpha", shadow: false, source: "gateway" },
      { ts: CREATED_AT, agent: "shadow-copilot", action_type: "tool_call_blocked", target: "openai.chat.completions", detail: "Shadow AI detected", tenant: "tenant-alpha", shadow: true, source: "gateway" },
    ],
  }));
  await page.route("**/v1/gateway/feed/kpis", (route) => fulfill(route, {
    schema_version: "gateway.feed.kpis.v1",
    tenant_id: "tenant-alpha",
    generated_at: CREATED_AT,
    calls_today: 4485,
    blocked_today: 247,
    shadow_ai_blocked: 247,
    data_filters_applied: 1320,
    tool_calls_authorized: 3918,
    llm_calls: 2106,
    uptime_seconds: 18720,
  }));
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
    env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
  });
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  return child;
}

async function capture(page, urlPath, filename, beforeShot, options = {}) {
  const responseWaits = (options.awaitResponses ?? []).map((predicate) =>
    page.waitForResponse(predicate, { timeout: 30_000 }),
  );
  if (responseWaits.length > 0) {
    await Promise.all([
      page.goto(`${BASE_URL}${urlPath}`, { waitUntil: "domcontentloaded" }),
      ...responseWaits,
    ]);
  } else {
    await page.goto(`${BASE_URL}${urlPath}`, { waitUntil: "domcontentloaded" });
  }
  await page.waitForLoadState("load");
  await page.waitForTimeout(urlPath.includes("capture=1") ? 1200 : 400);
  if (beforeShot) await beforeShot(page);
  if (urlPath.includes("capture=1")) {
    await page.locator("#demo-estate-watermark").waitFor({ state: "visible", timeout: 30_000 });
  }
  await page.screenshot({ path: path.join(IMAGE_DIR, filename), fullPage: false });
  console.log(`captured ${filename}`);
}

async function writeScreenshotManifest() {
  const screenshots = [
    {
      path: "dashboard-live.png",
      page: "/?capture=1",
      scope: "Overview command center — posture ring, findings breakdown, scan coverage, environment tabs",
    },
    {
      path: "dashboard-paths-live.png",
      page: "/?capture=1",
      scope: "Overview lower frame with exposure path and feed/analytics tabs",
    },
    {
      path: "cloud-accounts-live.png",
      page: "/connections?capture=1",
      scope: "Cloud accounts onboarding with provider catalog and account stats",
    },
    {
      path: "new-scan-live.png",
      page: "/scan?capture=1",
      scope: "New Scan form with connected account, ad-hoc, and public repo modes",
    },
    {
      path: "mesh-live.png",
      page: "/mesh?capture=1",
      scope: "Focused agent mesh graph across the active agent, MCP server, package, tool, and CVE path, cropped to the product graph surface",
    },
    {
      path: "gateway-policies-live.png",
      page: "/runtime?tab=gateway&capture=1",
      scope: "Runtime gateway KPI rollup and live tool-call feed",
    },
    {
      path: "security-graph-live.png",
      page: "/security-graph?capture=1",
      scope: "Fix-first attack path queue with snapshot pressure, graph evidence export, and remediation handoff",
    },
    {
      path: "lineage-graph-live.png",
      page: `/graph?capture=1&scan=${SCAN_ID}`,
      scope: "Expanded but bounded lineage topology across environment, identity, MCP, package, credential, model, dataset, and finding nodes",
    },
    {
      path: "context-map-live.png",
      page: "/context?capture=1",
      scope: "Agent-scoped context map showing reachable MCP servers and lateral movement side panel",
    },
    {
      path: "fleet-state-live.png",
      page: "/fleet?capture=1",
      scope: "Expanded fleet row showing lifecycle distribution, approved state, owner metadata, environment label, and discovery state",
    },
    {
      path: "identity-audit-live.png",
      page: "/audit?capture=1",
      scope: "Audit log filtered to identity resources with HMAC integrity counters and agent identity issue, rotate, revoke events",
    },
    {
      path: "dependency-map-live.png",
      page: "/findings?capture=1",
      scope: "Findings queue with seeded package and CVE evidence from the demo estate",
    },
    {
      path: "remediation-live.png",
      page: "/remediation?capture=1",
      scope: "Fix-first remediation table with prioritized packages and framework context",
    },
  ].map((entry) => ({ ...entry, visible_version: RELEASE_VERSION }));
  const manifest = {
    release_version: RELEASE_VERSION,
    captured_at: new Date().toISOString(),
    capture_note:
      "Captured from real Next.js dashboard routes in capture mode with a visible Demo data — sample environment label. The refreshed graph proof uses a deterministic Playwright harness that routes seeded scan, fleet, gateway, IAM, environment, runtime, and package evidence into the shipped pages so README media shows non-empty security graph, lineage topology, context map, fleet, and gateway states. The records are synthetic seeded evidence for docs proof, not a claim that those exact entities were discovered from a buyer environment.",
    screenshots,
  };
  await fs.writeFile(SCREENSHOT_MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`updated ${path.relative(REPO_ROOT, SCREENSHOT_MANIFEST)}`);
}

async function scrollTo(page, y) {
  await page.evaluate((targetY) => window.scrollTo({ top: targetY, behavior: "instant" }), y);
  await page.waitForTimeout(350);
}

async function fitReactFlow(page, { timeout = 30_000 } = {}) {
  await page.waitForSelector(".react-flow", { state: "visible", timeout });
  await page.waitForTimeout(250);
  await page.evaluate(() => {
    document.querySelector(".react-flow")?.scrollIntoView({ block: "center", inline: "center", behavior: "instant" });
  });
  await page.waitForTimeout(150);
  const fitButton = page.locator(".react-flow__controls-fitview").first();
  if ((await fitButton.count()) > 0) {
    try {
      await fitButton.click({ timeout: 5_000, force: true });
    } catch {
      await fitButton.dispatchEvent("click");
    }
  }
  await page.waitForTimeout(500);
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

    await capture(page, "/?capture=1", "dashboard-live.png");
    await capture(page, "/?capture=1", "dashboard-paths-live.png", async (dashboardPage) => {
      await scrollTo(dashboardPage, 720);
    });
    await capture(page, "/connections?capture=1", "cloud-accounts-live.png", async (connectionsPage) => {
      await connectionsPage.getByRole("heading", { name: "Cloud accounts" }).waitFor({ state: "visible", timeout: 10_000 });
    });
    await capture(page, "/scan?capture=1", "new-scan-live.png", async (scanPage) => {
      await scanPage.getByRole("heading", { name: /New Scan|Run scan/i }).first().waitFor({ state: "visible", timeout: 10_000 });
    });
    await capture(page, "/mesh?capture=1", "mesh-live.png");
    await capture(page, "/security-graph?capture=1", "security-graph-live.png");
    await capture(page, `/graph?capture=1&scan=${SCAN_ID}`, "lineage-graph-live.png", async (lineagePage) => {
      await fitReactFlow(lineagePage);
    });
    await capture(
      page,
      "/context?capture=1",
      "context-map-live.png",
      async (contextPage) => {
        await contextPage.getByText(/Lateral paths|Paths from|No lateral paths/i).first().waitFor({ state: "visible", timeout: 30_000 });
        const agentScope = contextPage.locator("select").first();
        if ((await agentScope.count()) > 0) {
          await agentScope.selectOption("");
          await contextPage.waitForTimeout(600);
        }
        try {
          await fitReactFlow(contextPage);
        } catch {
          await contextPage.waitForTimeout(500);
        }
      },
      {
        awaitResponses: [(response) => response.url().includes("/context-graph") && response.ok()],
      },
    );
    await capture(page, "/fleet?capture=1", "fleet-state-live.png", async (fleetPage) => {
      await fleetPage.getByText("developer-copilot").first().click({ force: true });
      await fleetPage.waitForTimeout(500);
      await scrollTo(fleetPage, 130);
    });
    await capture(page, "/runtime?tab=gateway&capture=1", "gateway-policies-live.png", async (gatewayPage) => {
      await gatewayPage.getByText("Calls today").first().waitFor({ state: "visible", timeout: 8000 });
      await gatewayPage.getByText("Gateway live feed").first().waitFor({ state: "visible", timeout: 8000 });
      await gatewayPage.waitForTimeout(400);
    });
    await capture(page, "/audit?capture=1", "identity-audit-live.png", async (auditPage) => {
      await auditPage.getByPlaceholder("Filter by resource…").fill("identity");
      await auditPage.waitForTimeout(350);
    });
    await capture(page, "/findings?capture=1", "dependency-map-live.png", async (findingsPage) => {
      await findingsPage.getByRole("heading", { name: /Findings|Issues|Vulnerabilit/i }).first().waitFor({
        state: "visible",
        timeout: 10_000,
      }).catch(async () => {
        await findingsPage.getByText(/CVE|critical|high|package/i).first().waitFor({ state: "visible", timeout: 8_000 });
      });
      await scrollTo(findingsPage, 200);
    });
    await capture(page, "/remediation?capture=1", "remediation-live.png");
    await writeScreenshotManifest();
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
