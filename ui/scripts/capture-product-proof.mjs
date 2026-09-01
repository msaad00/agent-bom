#!/usr/bin/env node
import { chromium } from "@playwright/test";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const REPO_ROOT = path.resolve(UI_ROOT, "..");
const IMAGE_DIR = path.join(REPO_ROOT, "docs", "images");
const SCREENSHOT_MANIFEST = path.join(IMAGE_DIR, "product-screenshots.json");
const REFERENCE_LAB_PROOF_PATH = path.join(
  REPO_ROOT,
  "examples",
  "reference-evidence-lab",
  "generated",
  "correlation-proof.json",
);
const REFERENCE_LAB_DIGEST_PATH = path.join(
  REPO_ROOT,
  "examples",
  "reference-evidence-lab",
  "generated",
  "correlation-proof.sha256",
);
const UI_PACKAGE = JSON.parse(await fs.readFile(path.join(UI_ROOT, "package.json"), "utf8"));
const RELEASE_VERSION = UI_PACKAGE.version;
const CREATED_AT = "2026-06-03T20:30:00Z";
const SCAN_ID = "scan-proof-ai-platform";
const PREVIOUS_SCAN_ID = "scan-proof-ai-platform-prev";
const SCENARIO_ID = "scenario-private-service-endpoint";
const CAPTURE_THEME = process.env.CAPTURE_THEME === "light" ? "light" : "dark";
const referenceLabProofBytes = await fs.readFile(REFERENCE_LAB_PROOF_PATH);
const referenceLabExpectedDigest = (await fs.readFile(REFERENCE_LAB_DIGEST_PATH, "utf8")).trim();
const referenceLabActualDigest = `sha256:${createHash("sha256").update(referenceLabProofBytes).digest("hex")}`;
if (referenceLabActualDigest !== referenceLabExpectedDigest) {
  throw new Error("Reference evidence lab proof is stale: regenerate the hash-pinned correlation artifact");
}
const REFERENCE_LAB = JSON.parse(referenceLabProofBytes.toString("utf8"));
if (
  REFERENCE_LAB.label !== "Reference evidence lab — modeled local infrastructure"
  || REFERENCE_LAB.correlation?.status !== "complete"
  || REFERENCE_LAB.capture_fixture?.graph?.scan_id !== REFERENCE_LAB.correlation?.output_scan_id
) {
  throw new Error("Reference evidence lab proof does not contain a completed correlated snapshot");
}
const REFERENCE_CORRELATION_ID = REFERENCE_LAB.correlation.correlation_id;
const referenceGraph = REFERENCE_LAB.capture_fixture.graph;
const referenceSnapshots = [
  {
    scan_id: REFERENCE_CORRELATION_ID,
    created_at: REFERENCE_LAB.correlation.completed_at,
    node_count: referenceGraph.nodes.length,
    edge_count: referenceGraph.edges.length,
    risk_summary: referenceGraph.stats.severity_counts,
    snapshot_kind: "correlation",
    correlation_id: REFERENCE_CORRELATION_ID,
    evidence_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
  },
  ...REFERENCE_LAB.capture_fixture.snapshots,
];

const baseUrlFromEnv = process.env.CAPTURE_BASE_URL;
if (baseUrlFromEnv) {
  throw new Error(
    "CAPTURE_BASE_URL is not allowed for release product proof; capture must use the local committed standalone build",
  );
}
const PORT = Number(process.env.CAPTURE_PORT || "3137");
const BASE_URL = `http://127.0.0.1:${PORT}`;
let captureOutputDir = IMAGE_DIR;
const execFileAsync = promisify(execFile);

async function captureSourceProvenance() {
  const [{ stdout: commit }, { stdout: status }] = await Promise.all([
    execFileAsync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT }),
    execFileAsync("git", ["status", "--porcelain"], { cwd: REPO_ROOT }),
  ]);
  if (status.trim()) {
    throw new Error("Release product proof requires a clean committed source tree, including no untracked inputs");
  }
  return { source_commit: commit.trim(), source_tree: "clean" };
}

async function screenshotSha256(filePath) {
  const digest = createHash("sha256").update(await fs.readFile(filePath)).digest("hex");
  return `sha256:${digest}`;
}

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
    node("cred:github", "credential", "DEMO_CRED_REF", "critical", 9.1, { safe_to_store: false }),
    node("cred:snowflake", "credential", "SNOWFLAKE_PROD_KEY", "critical", 9.3, { safe_to_store: false }),
    node("cred:aws", "credential", "AWS_ROLE_SESSION", "high", 8.1, { safe_to_store: false }),
    node("pkg:next", "package", "next@16.2.6", "critical", 9.2, { ecosystem: "npm", version: "16.2.6" }),
    node("pkg:urllib3", "package", "urllib3@2.4.0", "high", 8.5, { ecosystem: "pypi", version: "2.4.0" }),
    node("pkg:protobuf", "package", "protobuf@6.33.2", "high", 8.0, { ecosystem: "pypi", version: "6.33.2" }),
    node("pkg:langchain", "package", "langchain@0.3.21", "medium", 5.8, { ecosystem: "pypi", version: "0.3.21" }),
    node("cve:next", "vulnerability", "DEMO-VULN-21441", "critical", 9.8, { cvss_score: 9.8 }),
    node("cve:urllib3", "vulnerability", "DEMO-VULN-32597", "high", 8.8, { cvss_score: 8.8 }),
    node("cve:protobuf", "vulnerability", "DEMO-VULN-0994", "high", 8.1, { cvss_score: 8.1 }),
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
    edge("pkg:next", "cve:next", "vulnerable_to", 1.6, { cvss_score: 9.8 }),
    edge("pkg:urllib3", "cve:urllib3", "vulnerable_to", 1.4, { cvss_score: 8.8 }),
    edge("pkg:protobuf", "cve:protobuf", "vulnerable_to", 1.2, { cvss_score: 8.1 }),
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
      credential_exposure: ["DEMO_CRED_REF"],
      tool_exposure: ["create_pull_request"],
      vuln_ids: ["DEMO-VULN-21441"],
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
      vuln_ids: ["DEMO-VULN-32597"],
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
      vuln_ids: ["DEMO-VULN-0994"],
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
    analysis_status: {
      attack_path_fusion: {
        status: "complete",
        reason_codes: [],
        limits: { max_nodes: 5000, max_paths: 1000 },
        observed: { nodes: nodes.length, paths: attackPaths.length },
      },
    },
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

function graphScenario() {
  return {
    scenario_id: SCENARIO_ID,
    tenant_id: "default",
    base_scan_id: SCAN_ID,
    revision: 1,
    name: "Private service endpoint",
    description: "Replace public service access with a private endpoint and remove the credential-bearing edge.",
    assumptions: ["The private endpoint policy is deployed with least privilege."],
    changes: [],
    created_by: "platform-security",
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
  };
}

function graphScenarioComparison() {
  const proposedNode = node(
    `proposal:${SCENARIO_ID}:private-endpoint`,
    "cloud_resource",
    "Private service endpoint",
    "none",
    0,
    {
      evidence_state: "proposed",
      observed: false,
      deployed: false,
      scenario_id: SCENARIO_ID,
      scenario_revision: 1,
      assumption: "The private endpoint policy is deployed with least privilege.",
    },
  );
  proposedNode.status = "proposed";
  const removedEdge = "server:github->cred:github:exposes_cred";
  return {
    schema: "graph.scenario-comparison.v1",
    available: true,
    base_status: "available",
    stale: false,
    scenario: graphScenario(),
    current: {
      scan_id: SCAN_ID,
      node_count: graph.nodes.length,
      edge_count: graph.edges.length,
      completeness: {
        status: "complete",
        complete: true,
        sampled: false,
        truncated: false,
        returned: graph.nodes.length,
        total: graph.nodes.length,
      },
    },
    proposed: {
      scan_id: SCAN_ID,
      node_count: graph.nodes.length + 1,
      edge_count: graph.edges.length - 1,
      modeled: true,
      nodes: [...graph.nodes, proposedNode],
      edges: graph.edges.filter((item) => item.id !== removedEdge),
      completeness: {
        status: "complete",
        complete: true,
        sampled: false,
        truncated: false,
        returned: graph.nodes.length + 1,
        total: graph.nodes.length + 1,
      },
    },
    difference: {
      nodes_added: [proposedNode.id],
      nodes_removed: [],
      nodes_changed: ["server:github"],
      edges_added: [],
      edges_removed: [removedEdge],
      touched_observed_path_count: 1,
      touched_observed_path_ids: ["user:contractor->cve:next"],
    },
    comparison: {
      observed_path_count: graph.attack_paths.length,
      modeled_path_count: graph.attack_paths.length - 1,
      path_delta: -1,
      risk_delta: -1.8,
    },
    completeness: {
      status: "complete",
      complete: true,
      sampled: false,
      truncated: false,
      returned: graph.nodes.length + 1,
      total: graph.nodes.length + 1,
    },
  };
}

function contextGraph() {
  const nodes = [
    { id: "agent:developer-copilot", kind: "agent", label: "developer-copilot", metadata: { severity: "critical", agent_type: "ide" } },
    { id: "agent:sre-runbook", kind: "agent", label: "sre-runbook-agent", metadata: { severity: "high", agent_type: "runbook" } },
    { id: "agent:finance-rag", kind: "agent", label: "finance-rag-agent", metadata: { severity: "high", agent_type: "rag" } },
    { id: "iam:jit-review", kind: "iam_role", entity_type: "service_account", label: "jit-prod-reviewer", metadata: { severity: "high" } },
    { id: "server:github", kind: "server", label: "github-enterprise MCP", metadata: { severity: "critical" } },
    { id: "server:filesystem", kind: "server", label: "filesystem MCP", metadata: { severity: "critical" } },
    { id: "server:snowflake", kind: "server", label: "snowflake-rag MCP", metadata: { severity: "high" } },
    { id: "cred:github", kind: "credential", label: "DEMO_CRED_REF", metadata: { severity: "critical" } },
    { id: "cred:snowflake", kind: "credential", label: "SNOWFLAKE_PROD_KEY", metadata: { severity: "critical" } },
    { id: "tool:repo-write", kind: "tool", label: "create_pull_request", metadata: { severity: "high" } },
    { id: "tool:exec", kind: "tool", label: "execute_command", metadata: { severity: "critical" } },
    { id: "tool:query", kind: "tool", label: "run_sql", metadata: { severity: "high" } },
    { id: "cve:next", kind: "vulnerability", label: "DEMO-VULN-21441", metadata: { severity: "critical", cvss_score: 9.8 } },
    { id: "cve:urllib3", kind: "vulnerability", label: "DEMO-VULN-32597", metadata: { severity: "high", cvss_score: 8.8 } },
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
        credential_exposure: ["DEMO_CRED_REF"],
        tool_exposure: ["create_pull_request"],
        vuln_ids: ["DEMO-VULN-21441"],
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
        vuln_ids: ["DEMO-VULN-32597"],
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

function vuln(id, severity, cvss, fixedVersion) {
  return {
    id,
    severity,
    summary: `${id} reachable from an MCP-backed runtime path`,
    description: `${id} is present in a package reachable from agent tooling.`,
    references: [`urn:agent-bom:demo:${id}`],
    advisory_sources: ["demo-fixture"],
    cvss_score: cvss,
    fixed_version: fixedVersion,
    confidence: 0.98,
  };
}

const DEMO_AGENT_SPECS = [
  { name: "data-pipeline-agent", agent_type: "etl", owner: "data-platform", environment: "prod-analytics", server: "warehouse MCP", pkg: "pandas", version: "2.2.3", ecosystem: "pypi", cve: ["DEMO-VULN-44102", "high", 7.9, "2.2.4"] },
  { name: "customer-support-bot", agent_type: "support", owner: "cx-ops", environment: "prod-support", server: "zendesk MCP", pkg: "requests", version: "2.32.3", ecosystem: "pypi", cve: ["DEMO-VULN-11880", "medium", 6.4, "2.32.4"] },
  { name: "legal-review-agent", agent_type: "review", owner: "legal", environment: "prod-legal", server: "docusign MCP", pkg: "cryptography", version: "43.0.3", ecosystem: "pypi", cve: ["DEMO-VULN-55210", "high", 8.2, "44.0.1"] },
  { name: "hr-onboarding-agent", agent_type: "hr", owner: "people-ops", environment: "prod-hr", server: "workday MCP", pkg: "pillow", version: "11.1.0", ecosystem: "pypi", cve: null },
  { name: "marketing-copilot", agent_type: "marketing", owner: "growth", environment: "staging", server: "hubspot MCP", pkg: "react", version: "19.0.0", ecosystem: "npm", cve: ["DEMO-VULN-33011", "high", 8.0, "19.0.1"] },
  { name: "incident-commander", agent_type: "runbook", owner: "sre", environment: "prod-ai-control-plane", server: "pagerduty MCP", pkg: "aiohttp", version: "3.11.12", ecosystem: "pypi", cve: ["DEMO-VULN-77881", "critical", 9.1, "3.11.14"] },
  { name: "platform-ops-agent", agent_type: "ops", owner: "platform", environment: "prod-ai-control-plane", server: "kubernetes MCP", pkg: "kubernetes", version: "32.0.0", ecosystem: "pypi", cve: ["DEMO-VULN-90221", "high", 7.6, "32.0.2"] },
  { name: "ml-training-agent", agent_type: "ml", owner: "ml-platform", environment: "prod-ml", server: "wandb MCP", pkg: "torch", version: "2.6.0", ecosystem: "pypi", cve: ["DEMO-VULN-66110", "high", 8.4, "2.6.1"] },
  { name: "code-review-bot", agent_type: "ide", owner: "engineering", environment: "prod-ai-control-plane", server: "gitlab MCP", pkg: "eslint", version: "9.21.0", ecosystem: "npm", cve: null },
  { name: "compliance-auditor", agent_type: "audit", owner: "grc", environment: "prod-grc", server: "grc MCP", pkg: "pydantic", version: "2.10.6", ecosystem: "pypi", cve: ["DEMO-VULN-22001", "medium", 5.9, "2.10.7"] },
  { name: "vendor-risk-agent", agent_type: "risk", owner: "security", environment: "staging", server: "vendor MCP", pkg: "starlette", version: "0.45.3", ecosystem: "pypi", cve: ["DEMO-VULN-44190", "high", 7.8, "0.46.0"] },
  { name: "research-assistant", agent_type: "rag", owner: "research", environment: "staging", server: "arxiv MCP", pkg: "transformers", version: "4.49.0", ecosystem: "pypi", cve: ["DEMO-VULN-99120", "medium", 6.1, "4.49.2"] },
  { name: "sales-enablement-bot", agent_type: "sales", owner: "revenue", environment: "prod-sales", server: "salesforce MCP", pkg: "simple-salesforce", version: "1.12.6", ecosystem: "pypi", cve: null },
  { name: "devops-release-agent", agent_type: "release", owner: "devops", environment: "prod-ai-control-plane", server: "argocd MCP", pkg: "helm", version: "3.17.0", ecosystem: "pypi", cve: ["DEMO-VULN-55001", "high", 7.5, "3.17.1"] },
  { name: "shadow-copilot", agent_type: "shadow", owner: "unknown", environment: "unmanaged", server: "openai MCP", pkg: "openai", version: "1.66.3", ecosystem: "pypi", cve: ["DEMO-VULN-88001", "critical", 9.0, "1.66.5"] },
];

function demoScanAgent(spec) {
  const vulnerabilities = spec.cve
    ? [vuln(spec.cve[0], spec.cve[1], spec.cve[2], spec.cve[3])]
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
      vulnerability_id: "DEMO-VULN-21441",
      severity: "critical",
      package: "next",
      ecosystem: "npm",
      affected_agents: ["developer-copilot"],
      affected_servers: ["github-enterprise MCP"],
      exposed_credentials: ["DEMO_CRED_REF"],
      reachable_tools: ["create_pull_request"],
      blast_score: 98,
      risk_score: 9.8,
      cvss_score: 9.8,
      fixed_version: "16.2.7",
    },
    {
      vulnerability_id: "DEMO-VULN-32597",
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
      fixed_version: "2.5.1",
    },
    {
      vulnerability_id: "DEMO-VULN-0994",
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
      fixed_version: "6.33.4",
    },
    {
      vulnerability_id: "DEMO-VULN-77881",
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
      fixed_version: "3.11.14",
    },
    {
      vulnerability_id: "DEMO-VULN-88001",
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
      fixed_version: "1.66.5",
    },
  ];
  const seenIds = new Set(entries.map((item) => item.vulnerability_id));
  for (const spec of DEMO_AGENT_SPECS) {
    if (!spec.cve) continue;
    const [id, severity, cvss, , fixedVersion] = spec.cve;
    if (seenIds.has(id)) continue;
    seenIds.add(id);
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
    source: "demo-fixture",
    severity: item.severity,
    effective_severity: item.severity,
    title: `Reachable ${item.severity} package on ${item.affected_servers?.[0] ?? "MCP path"}`,
    description: `${item.vulnerability_id} is reachable from ${item.affected_agents.join(", ")} through simulated MCP tooling.`,
    cve_id: item.vulnerability_id,
    cvss_score: item.cvss_score,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    attack_vector: "network",
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
    total_vulnerabilities: 15,
    critical_findings: 3,
    high_findings: 9,
    medium_findings: 3,
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
          config_path: "/demo/workstation/.cursor/mcp.json",
          has_credentials: true,
          credential_env_vars: ["DEMO_CRED_REF"],
          tools: [{ name: "create_pull_request" }, { name: "read_repository" }],
          packages: [
            {
              name: "next",
              version: "16.2.6",
              ecosystem: "npm",
              purl: "pkg:npm/next@16.2.6",
              vulnerabilities: [vuln("DEMO-VULN-21441", "critical", 9.8, "16.2.7")],
            },
          ],
        },
        {
          name: "filesystem MCP",
          transport: "stdio",
          config_path: "/demo/workstation/.cursor/mcp.json",
          has_credentials: true,
          credential_env_vars: ["AWS_ROLE_SESSION"],
          tools: [{ name: "execute_command" }, { name: "read_file" }],
          packages: [
            {
              name: "urllib3",
              version: "2.4.0",
              ecosystem: "pypi",
              purl: "pkg:pypi/urllib3@2.4.0",
              vulnerabilities: [vuln("DEMO-VULN-32597", "high", 8.8, "2.5.1")],
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
              vulnerabilities: [vuln("DEMO-VULN-32597", "high", 8.8, "2.5.1")],
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
              vulnerabilities: [vuln("DEMO-VULN-0994", "high", 8.1, "6.33.4")],
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
      impact_score: 9.8,
      priority: 1,
      action: "upgrade",
      reason: "Critical reachable package on the highest-risk repo-write MCP path.",
      command: "npm install next@16.2.7",
      verify_command: "agent-bom scan --fail-on-severity high",
      vulnerabilities: ["DEMO-VULN-21441"],
      affected_agents: ["developer-copilot"],
      agents_pct: 33,
      exposed_credentials: ["DEMO_CRED_REF"],
      credentials_pct: 33,
      reachable_tools: ["create_pull_request"],
      tools_pct: 25,
      owasp_tags: ["LLM05", "LLM06"],
      atlas_tags: ["AML.T0051"],
      references: ["urn:agent-bom:demo:DEMO-VULN-21441"],
      risk_narrative: "Patch the package first because the affected server exposes repo-write tooling and a credential reference.",
    },
    {
      package: "urllib3",
      ecosystem: "pypi",
      current_version: "2.4.0",
      fixed_version: "2.5.1",
      severity: "high",
      impact_score: 8.9,
      priority: 2,
      action: "upgrade",
      reason: "Runbook agent reaches command tooling through the vulnerable dependency path.",
      command: "python -m pip install urllib3==2.5.1",
      verify_command: "agent-bom scan --fail-on-severity high",
      vulnerabilities: ["DEMO-VULN-32597"],
      affected_agents: ["sre-runbook-agent"],
      agents_pct: 33,
      exposed_credentials: ["AWS_ROLE_SESSION"],
      credentials_pct: 33,
      reachable_tools: ["execute_command"],
      tools_pct: 25,
      owasp_tags: ["LLM06"],
      atlas_tags: ["AML.T0054"],
      references: ["urn:agent-bom:demo:DEMO-VULN-32597"],
      risk_narrative: "Prioritize after the highest-risk demo path because it reaches shell-class tooling.",
    },
  ];
  return {
    job_id: SCAN_ID,
    status: "done",
    created_at: CREATED_AT,
    started_at: CREATED_AT,
    completed_at: "2026-06-03T20:32:00Z",
    request: { source_id: "source-proof-repo", path: "/workspace/sample-repository" },
    progress: [
      { step_id: "discovery", started_at: "2026-06-03T20:30:00Z", completed_at: "2026-06-03T20:30:12Z", message: "Discovered 15 synthetic agents", stats: { agents: 15 } },
      { step_id: "extraction", started_at: "2026-06-03T20:30:12Z", completed_at: "2026-06-03T20:30:28Z", message: "Extracted package and source inventory", stats: { packages: 126 } },
      { step_id: "scanning", started_at: "2026-06-03T20:30:28Z", completed_at: "2026-06-03T20:31:16Z", message: "Completed configured read-only scanners", stats: { findings: 15 } },
      { step_id: "enrichment", started_at: "2026-06-03T20:31:16Z", completed_at: "2026-06-03T20:31:34Z", message: "Attached local advisory and policy context", stats: { enriched: 15 } },
      { step_id: "analysis", started_at: "2026-06-03T20:31:34Z", completed_at: "2026-06-03T20:31:53Z", message: "Calculated reachability and bounded paths", stats: { paths: 3 } },
      { step_id: "output", started_at: "2026-06-03T20:31:53Z", completed_at: "2026-06-03T20:32:00Z", message: "Persisted findings, graph, and report evidence", stats: { reports: 1 } },
    ].map((event) => JSON.stringify({ type: "step", status: "done", ...event })),
    summary: scanSummary(agents.length),
    result: {
      agents,
      blast_radius: buildBlastRadius(),
      remediation_plan: remediationPlan,
      scan_sources: ["demo-scan", "fleet-sync", "gateway-runtime"],
    },
  };
}

function agentLifecycleFixture() {
  const nodes = [
    ["agent", "developer-copilot", 40, 220, {}],
    ["server", "github-enterprise MCP", 300, 100, {}],
    ["server", "filesystem MCP", 300, 340, {}],
    ["package", "next", 570, 80, { version: "16.2.6", ecosystem: "npm" }],
    ["tool", "create_pull_request", 570, 220, {}],
    ["credential", "DEMO_CRED_REF", 570, 360, { description: "Reference only; no value" }],
    ["cve", "DEMO-VULN-21441", 840, 80, { severity: "critical", fixed_version: "16.2.7" }],
  ].map(([nodeType, label, x, y, extra], index) => ({
    id: `lifecycle-${index + 1}`,
    type: "lifecycleNode",
    position: { x, y },
    data: { nodeType, label, ...extra },
  }));
  const edges = [
    [0, 1], [0, 2], [1, 3], [1, 4], [1, 5], [3, 6],
  ].map(([source, target], index) => ({
    id: `lifecycle-edge-${index + 1}`,
    source: nodes[source].id,
    target: nodes[target].id,
    type: "smoothstep",
  }));
  return {
    nodes,
    edges,
    stats: {
      total_servers: 2,
      total_packages: 1,
      total_tools: 1,
      total_credentials: 1,
      total_vulnerabilities: 1,
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

function referenceFixFirstView() {
  const pathItem = referenceGraph.attack_paths[0];
  const nodesById = new Map(referenceGraph.nodes.map((item) => [item.id, item]));
  const digest = REFERENCE_LAB.container_digest;
  return {
    scan_id: REFERENCE_CORRELATION_ID,
    tenant_id: REFERENCE_LAB.correlation.tenant_id,
    created_at: REFERENCE_LAB.correlation.completed_at,
    cards: [{
      id: "reference-lab-path-1",
      rank: 1,
      title: "Public service reaches modeled customer records through CVE-2023-4863",
      summary: `${REFERENCE_LAB.label}. Exact digest ${digest} contains pillow@9.0.0 and CVE-2023-4863. The gateway observed the correlated tool call; strict opt-in policy ${REFERENCE_LAB.runtime_control.policy_id} then blocked the same canonical tool and runtime.`,
      attack_path: pathItem,
      nodes: referenceGraph.nodes,
      sequence_labels: pathItem.hops.map((hop) => {
        const nodeItem = nodesById.get(hop);
        if (nodeItem?.entity_type === "container") return `reference-evidence-api@${digest}`;
        return nodeItem?.label ?? hop;
      }),
      risk_reasons: [
        { kind: "exact_identity", label: "Exact identities", detail: "PURL, OCI digest, Kubernetes UID, stable MCP tool ID, and provider identity receipts support every cross-source join." },
        { kind: "runtime_observed", label: "Runtime observed", detail: `Observed event ${REFERENCE_LAB.runtime_control.observed_event} binds the same runtime and tool.` },
        { kind: "runtime_blocked", label: "Runtime blocked", detail: `Strict deny event ${REFERENCE_LAB.runtime_control.blocked_event} verifies the opt-in enforcement path.` },
      ],
      next_actions: [
        { title: "Patch Pillow and re-run correlation", detail: "Upgrade the vulnerable package, rebuild the digest, then verify the correlated path is absent.", href: "/remediation" },
      ],
      affected: {
        agents: pathItem.hops.filter((hop) => hop.startsWith("workload:")),
        servers: pathItem.hops.filter((hop) => hop.startsWith("service:")),
        packages: pathItem.hops.filter((hop) => hop.startsWith("package:")),
        findings: pathItem.vuln_ids,
        credentials: pathItem.hops.filter((hop) => hop.startsWith("identity:")),
        tools: pathItem.hops.filter((hop) => hop.startsWith("tool:")),
      },
    }],
    summary: {
      total_paths: referenceGraph.attack_paths.length,
      matched_paths: 1,
      returned_paths: 1,
      highest_risk: pathItem.composite_risk,
      covered_findings: pathItem.vuln_ids.length,
      node_count: referenceGraph.nodes.length,
      edge_count: referenceGraph.edges.length,
    },
    focus: { cve: "CVE-2023-4863", package: "pillow", agent: "" },
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
  const domain = (label, href, metric, metricLabel, status, detail = {}, graphHref) => ({
    label,
    href,
    ...(graphHref ? { graph_href: graphHref } : {}),
    metric,
    metric_label: metricLabel,
    status,
    detail,
  });
  // Reachable-CVE histogram for the demo estate — sums to the 15 unique findings
  // so the metric never contradicts its severity strip (overview honesty rule).
  const vulnSeverity = { critical: 3, high: 9, medium: 3, low: 0, unrated: 0 };
  const zeroSeverity = { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 };
  // Coverage lanes are overlapping posture lenses, not a partition: the demo's
  // Fifteen unique reachable CVEs appear in both the vulnerability and AI-posture lenses.
  const coverage = [
    { domain: "cspm", label: "CSPM", href: "/findings?domain=cspm", count: 0, severity: { ...zeroSeverity } },
    { domain: "vuln", label: "Vuln mgmt", href: "/findings?domain=vuln", count: 15, severity: { ...vulnSeverity } },
    { domain: "aspm", label: "AppSec / ASPM", href: "/findings?domain=aspm", count: 0, severity: { ...zeroSeverity } },
    { domain: "dspm", label: "DSPM", href: "/findings?domain=dspm", count: 0, severity: { ...zeroSeverity } },
    { domain: "aispm", label: "AISPM", href: "/findings?domain=aispm", count: 15, severity: { ...vulnSeverity } },
  ];
  return {
    schema_version: "overview.v1",
    tenant_id: "default",
    posture: {
      grade: "D",
      score: 43,
      summary: "Reachable agent, MCP, credential, and package evidence is normalized into one operator queue.",
    },
    headline: {
      critical: 3,
      high: 9,
      critical_high: 12,
      credential_exposed: 3,
      scans: 3,
      latest_scan_at: CREATED_AT,
      hub_findings: 15,
    },
    coverage,
    domains: {
      cloud: domain("Cloud posture", "/connections", 4, "accounts connected", "ok", { accounts: 4, sources: ["demo-scan"] }),
      vuln: domain(
        "Vuln / SCA",
        "/findings?issue=vulnerability",
        15,
        "open CVEs",
        "critical",
        { critical: 3, high: 9, packages: 148, severity: { ...vulnSeverity } },
      ),
      code: domain("Code / repo", "/scan", 3, "repo scans", "ok", { repo_scans: 3, packages: 148 }),
      runtime: domain("Runtime", "/gateway", 247, "active surfaces", "critical", { active_surfaces: 247 }),
      cost: domain("LLM Cost", "/cost", 18.4, "USD tracked", "ok", { total_cost_usd: 18.4, total_calls: 2106 }),
      identity: domain("NHI / Identity", "/identity", 18, "identities + agents", "warn", { managed_identities: 3, fleet_agents: 15 }),
      ops: domain("Ops", "/jobs", 3, "completed scans", "ok", { done: 3, failed: 0, running: 0, packages: 148 }),
    },
    top_risks: [
      {
        vulnerability_id: "DEMO-VULN-21441",
        package: "next",
        severity: "critical",
        risk_score: 9.8,
        cvss_score: 9.8,
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
    ["scan.completed", "api", "scan/" + SCAN_ID, { findings: 15, graph_nodes: graph.nodes.length }],
    ["gateway.policy.denied", "gateway", "tool/execute_command", { agent: "developer-copilot", rule: "block-shell" }],
    ["agent_identity.issued", "api", "identity/id_89c1a6f406bd7189", { tenant: "default" }],
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

const INVENTORY_FINDING_TYPES = new Set([
  "finding",
  "vulnerability",
  "misconfiguration",
  "secret",
  "pii_exposure",
]);

function inventoryFindingSummary(nodeId) {
  const findingIds = graph.edges
    .filter((item) => item.source === nodeId || item.target === nodeId)
    .map((item) => (item.source === nodeId ? item.target : item.source))
    .filter((id) => INVENTORY_FINDING_TYPES.has(graph.nodes.find((item) => item.id === id)?.entity_type));
  const findings = findingIds.map((id) => graph.nodes.find((item) => item.id === id)).filter(Boolean);
  const bySeverity = findings.reduce(
    (counts, item) => ({ ...counts, [item.severity]: (counts[item.severity] ?? 0) + 1 }),
    {},
  );
  const topSeverity = findings
    .map((item) => item.severity)
    .sort((left, right) => severityId(right) - severityId(left))[0] ?? "none";
  return { total: findings.length, by_severity: bySeverity, ids: findingIds, top_severity: topSeverity };
}

function inventoryAssetRows() {
  return graph.nodes
    .filter((item) => !INVENTORY_FINDING_TYPES.has(item.entity_type))
    .map((item) => {
      const relatedEdges = graph.edges.filter((edgeItem) => edgeItem.source === item.id || edgeItem.target === item.id);
      return {
        id: item.id,
        type: item.entity_type,
        name: item.label,
        environment: item.dimensions?.environment ?? item.attributes?.environment ?? "",
        provider: item.dimensions?.cloud_provider ?? item.attributes?.provider ?? "",
        risk: item.risk_score,
        severity: item.severity,
        status: item.status,
        source: item.data_sources?.[0] ?? "",
        sources: item.data_sources ?? [],
        first_seen: item.first_seen,
        last_seen: item.last_seen,
        attributes: item.attributes ?? {},
        compliance_tags: item.compliance_tags ?? [],
        ecosystem: item.dimensions?.ecosystem ?? item.attributes?.ecosystem ?? "",
        version: item.attributes?.version ?? "",
        finding_summary: inventoryFindingSummary(item.id),
        relationship_count: relatedEdges.length,
      };
    });
}

function inventoryBuckets(rows, dimension) {
  const counts = new Map();
  for (const row of rows) {
    let values;
    if (dimension === "type") values = [row.type || null];
    else if (dimension === "source") values = row.sources.length > 0 ? row.sources : [null];
    else if (dimension === "severity") {
      values = [row.finding_summary.total > 0 ? row.finding_summary.top_severity : null];
    } else values = [row[dimension] || null];
    for (const value of new Set(values)) counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || String(left.value).localeCompare(String(right.value)));
}

function inventoryFacets(rows) {
  return Object.fromEntries(
    ["type", "source", "provider", "environment", "severity"].map((dimension) => [
      dimension,
      { buckets: inventoryBuckets(rows, dimension) },
    ]),
  );
}

function inventorySummaryFixture() {
  const rows = inventoryAssetRows();
  const byType = Object.fromEntries(
    inventoryBuckets(rows, "type")
      .filter((item) => item.value)
      .map((item) => [item.value, item.count]),
  );
  return {
    schema_version: "inventory.summary.v1",
    tenant_id: "default",
    scan_id: SCAN_ID,
    created_at: CREATED_AT,
    total_assets: rows.length,
    by_type: byType,
    by_group: {},
    finding_count: graph.nodes.filter((item) => INVENTORY_FINDING_TYPES.has(item.entity_type)).length,
    facets: inventoryFacets(rows),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SCAN_ID },
    completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: rows.length, total: rows.length },
  };
}

function inventoryAssetsFixture(requestUrl) {
  const url = new URL(requestUrl);
  const requestedTypes = new Set((url.searchParams.get("type") ?? "").split(",").filter(Boolean));
  const query = (url.searchParams.get("search") ?? "").toLowerCase();
  const environment = url.searchParams.get("environment") ?? "";
  const provider = url.searchParams.get("provider") ?? "";
  const source = url.searchParams.get("source") ?? "";
  const severity = url.searchParams.get("severity") ?? "";
  const allRows = inventoryAssetRows();
  const rows = allRows.filter((row) => {
    if (requestedTypes.size > 0 && !requestedTypes.has(row.type)) return false;
    if (query && !`${row.id} ${row.name} ${row.type} ${row.sources.join(" ")}`.toLowerCase().includes(query)) return false;
    if (environment && row.environment !== environment) return false;
    if (provider && row.provider !== provider) return false;
    if (source && !row.sources.includes(source)) return false;
    if (severity && row.finding_summary.top_severity !== severity) return false;
    return true;
  });
  const limit = Number(url.searchParams.get("limit") ?? 100);
  const offset = Number(url.searchParams.get("offset") ?? 0);
  const pageRows = rows.slice(offset, offset + limit);
  const hasMore = offset + pageRows.length < rows.length;
  return {
    schema_version: "inventory.assets.v1",
    tenant_id: "default",
    scan_id: SCAN_ID,
    created_at: CREATED_AT,
    assets: pageRows,
    filters: { type: [...requestedTypes], search: query, environment, provider, source, severity },
    pagination: { total: rows.length, offset, limit, cursor: "", next_cursor: "", has_more: hasMore, facet_filtered: Boolean(environment || provider || source || severity) },
    facets: inventoryFacets(rows),
    facet_metadata: { basis: "whole_query", mode: "self_excluding", exact: true, scan_id: SCAN_ID },
    completeness: { status: hasMore ? "truncated" : "complete", complete: !hasMore, sampled: false, truncated: hasMore, returned: pageRows.length, total: rows.length, ...(hasMore ? { reason: "asset_page_limit" } : {}) },
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
  // The gateway live-feed panel opens the proxy metrics WebSocket on mount. With
  // no backend behind the capture dev server the handshake would fail and emit a
  // fatal console error, so mock the socket here: accept the client connection
  // (fires onopen → "live" indicator) and stream a single metrics tick.
  await page.routeWebSocket(/\/ws\/proxy\/metrics/, (ws) => {
    ws.onMessage(() => {});
    ws.send(JSON.stringify({ total_tool_calls: 4485, total_blocked: 247 }));
  });
  await page.route("**/health", (route) => fulfill(route, { status: "ok", version: RELEASE_VERSION }));
  await page.route("**/v1/compliance", (route) => fulfill(route, {
    overall_score: 72,
    overall_status: "warning",
    evaluated_controls: 12,
    total_controls: 12,
    coverage_pct: 100,
    scan_count: 2,
    latest_scan: CREATED_AT,
    has_mcp_context: true,
    has_agent_context: true,
    scan_sources: ["demo-fixture"],
    framework_kinds: {
      owasp_llm_top10: "applicability",
      owasp_mcp_top10: "applicability",
      mitre_atlas: "applicability",
      nist_ai_rmf: "scored",
      owasp_agentic_top10: "applicability",
      eu_ai_act: "scored",
      nist_csf: "scored",
      iso_27001: "scored",
      soc2: "scored",
      cis_controls: "scored",
      cmmc: "scored",
      nist_800_53: "scored",
      fedramp: "scored",
      pci_dss: "scored",
    },
    owasp_llm_top10: [],
    owasp_mcp_top10: [],
    mitre_atlas: [],
    nist_ai_rmf: [],
    owasp_agentic_top10: [],
    eu_ai_act: [],
    nist_csf: [],
    iso_27001: [],
    soc2: [],
    cis_controls: [],
    cmmc: [],
    nist_800_53: [],
    fedramp: [],
    pci_dss: [],
    summary: {},
  }));
  await page.route("**/v1/cloud/connections", (route) => fulfill(route, {
    schema_version: "cloud.connections.v1",
    tenant_id: "default",
    connections: [{
      id: "conn-proof-aws-prod",
      tenant_id: "default",
      provider: "aws",
      display_name: "Demo AWS production",
      role_ref: "arn:aws:iam::111122223333:role/AgentBomDemoReadOnly",
      has_external_id: true,
      regions: ["us-east-1", "us-west-2"],
      status: "active",
      status_detail: "",
      created_at: CREATED_AT,
      updated_at: CREATED_AT,
      last_scan_at: CREATED_AT,
      last_event_at: null,
      last_scan_id: SCAN_ID,
      scan_interval_minutes: 360,
      auth_params: {},
    }],
    count: 1,
  }));
  await page.route("**/v1/sources", (route) => fulfill(route, {
    schema_version: "sources.v1",
    tenant_id: "default",
    sources: [{
      source_id: "source-proof-repo",
      tenant_id: "default",
      display_name: "Demo platform repositories",
      kind: "scan.repo",
      description: "Synthetic repository source for product proof.",
      owner: "platform-security",
      connector_name: null,
      credential_mode: "none",
      credential_ref: null,
      enabled: true,
      status: "healthy",
      config: {},
      last_tested_at: CREATED_AT,
      last_test_status: "healthy",
      last_test_message: "Synthetic demo source",
      last_run_at: CREATED_AT,
      last_run_status: "completed",
      last_job_id: SCAN_ID,
      created_at: CREATED_AT,
      updated_at: CREATED_AT,
    }],
    count: 1,
  }));
  await page.route("**/v1/connectors", (route) => fulfill(route, { connectors: [] }));
  await page.route("**/v1/schedules", (route) => fulfill(route, []));
  await page.route("**/v1/ticketing/tickets", (route) => fulfill(route, {
    schema_version: "ticketing.tickets.v1",
    tenant_id: "default",
    tickets: [],
    count: 0,
  }));
  await page.route("**/v1/ticketing/connections", (route) => fulfill(route, {
    schema_version: "ticketing.connections.v1",
    tenant_id: "default",
    connections: [],
    count: 0,
  }));
  await page.route("**/v1/campaigns/verification-queue**", (route) => fulfill(route, {
    schema_version: "risk-campaign-verification-queue.v1",
    tenant_id: "tenant-proof",
    entries: [],
    count: 0,
    limit: 25,
    has_more: false,
    next_cursor: null,
  }));
  await page.route("**/v1/campaigns", (route) => fulfill(route, {
    schema_version: "risk-campaigns.v1",
    tenant_id: "default",
    campaigns: [{
      id: "campaign-demo-openssl",
      tenant_id: "default",
      title: "Upgrade openssl to 3.0.14",
      finding_ids: ["DEMO-VULN-21441", "DEMO-VULN-32597"],
      finding_count: 2,
      severity: "critical",
      priority_score: 9.2,
      priority_score_method: "maximum finding risk; context factors do not modify the score",
      score_factors: {
        severity: { value: "critical", status: "observed", bands_present: ["critical", "high"] },
        exploitability: { value: null, status: "unknown" },
        reachability: { value: true, status: "observed" },
        business_context: { value: "Production AI gateway", status: "observed" },
      },
      expected_risk_reduction: {
        modeled_window_percent: 42.5,
        modeled_risk_points: 18.1,
        assumption: "all campaign findings are remediated and verified",
        method: "campaign modeled risk divided by modeled risk in the bounded findings window",
        scope: "last 90 days, first 1000 findings",
        portfolio_complete: true,
      },
      owner: "platform-security",
      sla_due_at: "2026-07-24T00:00:00Z",
      state: "in_progress",
      verification_status: "pending",
      updated_at: CREATED_AT,
      source: "canonical_findings_spine",
      membership_fingerprint: "demo-membership-fingerprint",
      generation: 1,
      version: 1,
      active: true,
      membership_complete: true,
      membership_provisional: false,
    }],
    count: 1,
    finding_window_days: 90,
    finding_limit: 1000,
    truncated: false,
    total_findings: 2,
    total_approximate: false,
    membership_complete: true,
  }));
  await page.route("**/v1/discovery/providers", (route) => fulfill(route, {
    contract_version: "1",
    entrypoints_enabled: false,
    provider_count: 0,
    warnings: [],
    providers: [],
  }));
  await page.route("**/version", (route) => fulfill(route, { version: RELEASE_VERSION, name: "agent-bom" }));
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
    critical: 3,
    high: 9,
    medium: 3,
    low: 0,
    total: 15,
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
    services: {
      cloud_accounts: { state: "live", count: 1 },
      data_sources: { state: "live", count: 1 },
    },
  }));
  await page.route("**/v1/posture", (route) => fulfill(route, {
    grade: "D",
    score: 43,
    summary: "15 unique findings across MCP, identity, runtime policy, and package reachability.",
    dimensions: {
      exploitability: { score: 18, label: "Exploitability", details: "Critical CVE is reachable from repo-write MCP." },
      identity: { score: 34, label: "Identity", details: "JIT reviewer can assume prod AI role." },
      runtime: { score: 61, label: "Runtime", details: "Gateway blocks high-risk tool classes." },
    },
  }));
  await page.route("**/v1/trends?**", (route) => fulfill(route, {
    data_points: [
      {
        scan_id: SCAN_ID,
        timestamp: CREATED_AT,
        total_vulns: 15,
        critical: 3,
        high: 9,
        medium: 3,
        low: 0,
        posture_score: 43,
        posture_grade: "D",
      },
      {
        scan_id: "scan-proof-baseline",
        timestamp: "2026-07-16T19:45:00Z",
        total_vulns: 18,
        critical: 4,
        high: 10,
        medium: 4,
        low: 0,
        posture_score: 37,
        posture_grade: "F",
      },
    ],
    count: 2,
  }));
  await page.route("**/v1/overview", (route) => fulfill(route, overviewResponse()));
  await page.route("**/v1/agents", (route) => fulfill(route, {
    agents: scanJob().result.agents,
    count: scanJob().result.agents.length,
    warnings: [],
  }));
  await page.route("**/v1/agents/developer-copilot/lifecycle", (route) => fulfill(route, agentLifecycleFixture()));
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
  // `/remediation` reads the dedicated plan endpoint rather than pulling the
  // whole scan job for one field. Without this the page falls through to the
  // live API, which has no such job, and the capture fails on missing content.
  await page.route((url) => {
    try {
      return new URL(url).pathname === `/v1/scan/${SCAN_ID}/remediation`;
    } catch {
      return false;
    }
  }, (route) => {
    const plan = scanJob().result.remediation_plan;
    return fulfill(route, { job_id: SCAN_ID, remediation_plan: plan, total: plan.length });
  });
  await page.route((url) => {
    try {
      return new URL(url).pathname === `/v1/scan/${SCAN_ID}`;
    } catch {
      return false;
    }
  }, (route) => fulfill(route, scanJob()));
  await page.route("**/v1/graph/snapshots?**", (route) => fulfill(route, [
    ...referenceSnapshots,
    { scan_id: SCAN_ID, created_at: CREATED_AT, node_count: graph.nodes.length, edge_count: graph.edges.length, risk_summary: graph.stats.severity_counts },
    { scan_id: PREVIOUS_SCAN_ID, created_at: "2026-06-03T19:00:00Z", node_count: 22, edge_count: 25, risk_summary: { critical: 5, high: 8, medium: 6 } },
  ]));
  await page.route(
    (url) => {
      try {
        return new URL(url).pathname === "/v1/inventory/summary";
      } catch {
        return false;
      }
    },
    (route) => fulfill(route, inventorySummaryFixture()),
  );
  await page.route("**/v1/inventory/assets?**", (route) => fulfill(route, inventoryAssetsFixture(route.request().url())));
  await page.route("**/v1/inventory/assets/**", (route) => {
    const url = new URL(route.request().url());
    const assetId = decodeURIComponent(url.pathname.split("/").at(-1) ?? "");
    const asset = inventoryAssetRows().find((item) => item.id === assetId);
    const selected = graph.nodes.find((item) => item.id === assetId);
    if (!asset || !selected) return fulfill(route, { detail: "Asset not found" }, 404);
    return fulfill(route, {
      schema_version: "inventory.asset.v1",
      tenant_id: "default",
      asset,
      node: selected,
      edges_out: graph.edges.filter((item) => item.source === assetId),
      edges_in: graph.edges.filter((item) => item.target === assetId),
      neighbors: graph.edges.filter((item) => item.source === assetId || item.target === assetId).flatMap((item) => [item.source, item.target]).filter((id) => id !== assetId),
      sources: asset.sources,
      impact: { node_id: assetId, affected_nodes: [], affected_by_type: {}, affected_count: 0, max_depth_reached: 0 },
      completeness: { status: "complete", complete: true, sampled: false, truncated: false, returned: 1, total: 1 },
    });
  });
  await page.route("**/v1/graph/views/fix-first?**", (route) => {
    const url = new URL(route.request().url());
    return fulfill(route, url.searchParams.get("scan_id") === REFERENCE_CORRELATION_ID ? referenceFixFirstView() : fixFirstView());
  });
  await page.route((url) => url.pathname === "/v1/graph/correlations", (route) => {
    if (route.request().method() === "POST") return fulfill(route, REFERENCE_LAB.correlation, 202);
    return fulfill(route, { items: [REFERENCE_LAB.correlation], count: 1 });
  });
  await page.route(
    (url) => url.pathname === `/v1/graph/correlations/${REFERENCE_CORRELATION_ID}`,
    (route) => fulfill(route, REFERENCE_LAB.correlation),
  );
  await page.route("**/v1/graph/presets**", (route) => fulfill(route, []));
  await page.route(`**/v1/graph/scenarios/${SCENARIO_ID}/comparison?**`, (route) =>
    fulfill(route, graphScenarioComparison()),
  );
  await page.route("**/v1/graph/scenarios", (route) => fulfill(route, {
    schema: "graph.scenarios.v1",
    count: 1,
    scenarios: [graphScenario()],
  }));
  await page.route("**/v1/graph/rollup?**", (route) => fulfill(route, {
    scan_id: SCAN_ID,
    tenant_id: "default",
    created_at: CREATED_AT,
    mode: "rollup",
    filters: { min_severity: "high" },
    top_level: graph.nodes.slice(0, 30).map((node) => ({
      id: node.id,
      label: node.label,
      entity_type: node.entity_type,
      severity: node.severity,
      is_container: true,
      has_children: true,
      direct_child_count: 3,
      aggregate: {
        descendant_count: 12,
        by_type: { agent: 2, server: 3, package: 4, vulnerability: 3 },
        severity_counts: { critical: 2, high: 4, medium: 3, low: 0 },
        worst_severity: node.severity,
        worst_severity_rank: severityId(node.severity),
        internet_exposed: node.severity === "critical",
        toxic_combo: node.severity === "critical",
        exposed_count: node.severity === "critical" ? 2 : 0,
        toxic_count: node.severity === "critical" ? 1 : 0,
      },
    })),
    summary: {
      total_nodes: graph.nodes.length,
      total_nodes_source: graph.nodes.length,
      total_edges: graph.edges.length,
      container_count: 30,
      severity_counts: graph.stats.severity_counts,
    },
    edges: [
      {
        source: graph.nodes[0].id,
        target: graph.nodes[1].id,
        count: 1,
        relationships: ["hosts"],
      },
    ],
    completeness: {
      returned: 30,
      total: 30,
      truncated: false,
      reason: "",
    },
    edge_count_metadata: {
      definition: "aggregated non-containment relationship rows between returned containers",
      source_total: 1,
      returned: 1,
      truncated: false,
      source_truncated: false,
      reason: "",
    },
  }));
  await page.route("**/v1/graph/attack-paths?**", (route) => {
    const url = new URL(route.request().url());
    const selectedGraph = url.searchParams.get("scan_id") === REFERENCE_CORRELATION_ID ? referenceGraph : graph;
    return fulfill(route, graphResponseWithPagination(selectedGraph));
  });
  await page.route("**/v1/graph/exposure-paths?**", (route) => fulfill(route, {
    schema_version: "exposure-paths.v1",
    tool: "agent_bom_exposure_paths",
    tenant_id: "default",
    scan_id: SCAN_ID,
    created_at: CREATED_AT,
    count: 0,
    total: 0,
    filters: { limit: 25, min_risk: 0 },
    paths: [],
    message: "No separately materialized demo exposure paths; attack-path graph evidence is shown below.",
  }));
  await page.route("**/v1/graph/diff?**", (route) => fulfill(route, {
    nodes_added: ["sa:jit-review", "role:prod-admin", "policy:gateway-default-deny", "cve:next"],
    nodes_removed: [],
    nodes_changed: ["agent:developer-copilot", "server:github", "cred:github"],
    edges_added: [["sa:jit-review", "role:prod-admin", "assumes"], ["policy:gateway-default-deny", "tool:exec", "manages"]],
    edges_removed: [],
  }));
  await page.route("**/v1/graph/edges/changes?**", (route) => fulfill(route, {
    old_scan_id: PREVIOUS_SCAN_ID,
    new_scan_id: SCAN_ID,
    added: [],
    removed: [],
    changed: [],
    count: 0,
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
  await page.route((url) => url.pathname === "/v1/graph", (route) => {
    const url = new URL(route.request().url());
    return fulfill(route, graphResponseWithPagination(url.searchParams.get("scan_id") === REFERENCE_CORRELATION_ID ? referenceGraph : graph));
  });
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
  await page.route("**/v1/findings/triage?**", (route) => fulfill(route, {
    schema_version: "findings.triage.v1",
    triage: [],
    total: 0,
    limit: 1000,
    offset: 0,
  }));
  await page.route("**/v1/fleet/endpoints?**", (route) => fulfill(route, {
    endpoints: [
      {
        endpoint_id: "workstation-01",
        tenant_id: "default",
        platform: { system: "Darwin", release: "15.6", machine: "arm64" },
        counts: {
          applications: 42,
          processes: 118,
          services: 16,
          listeners: 9,
          containers: 6,
          images: 11,
        },
        collector_status: {
          applications: "complete",
          processes: "complete",
          services: "complete",
          listeners: "complete",
          containers: "complete",
          images: "complete",
        },
        collector_messages: {},
        privacy: { process_arguments_collected: false, environment_values_collected: false },
        completeness: "complete",
        last_scan_id: SCAN_ID,
        observed_at: CREATED_AT,
        updated_at: CREATED_AT,
      },
    ],
    count: 1,
    total: 1,
    limit: 25,
    offset: 0,
    has_more: false,
  }));
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
    const url = new URL(route.request().url());
    const resource = (url.searchParams.get("resource") ?? "").trim().toLowerCase();
    const entries = auditEntries().filter((entry) => !resource || entry.resource.toLowerCase().includes(resource));
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
    health: {
      state: "sample",
      live: false,
      heartbeat_at: CREATED_AT,
      age_seconds: 0,
      stale_after_seconds: 120,
      reason: "deterministic_capture",
    },
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

async function startServerIfNeeded() {
  const standaloneRoot = path.join(UI_ROOT, ".next", "standalone");
  const standaloneStatic = path.join(standaloneRoot, ".next", "static");
  const standalonePublic = path.join(standaloneRoot, "public");
  await fs.cp(path.join(UI_ROOT, ".next", "static"), standaloneStatic, { recursive: true });
  await fs.cp(path.join(UI_ROOT, "public"), standalonePublic, { recursive: true });
  const child = spawn(process.execPath, ["server.js"], {
    cwd: standaloneRoot,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      HOSTNAME: "127.0.0.1",
      PORT: String(PORT),
      NEXT_TELEMETRY_DISABLED: "1",
    },
  });
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  return child;
}

async function stopServer(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  const stopped = await Promise.race([
    exited.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 5_000)),
  ]);
  if (!stopped && child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await exited;
  }
}

function isBenignAppRouterCancellation(request, failure) {
  if (failure !== "net::ERR_ABORTED" || request.resourceType() !== "fetch") return false;
  const requestUrl = new URL(request.url());
  return requestUrl.searchParams.has("_rsc");
}

async function capture(page, urlPath, filename, beforeShot, options = {}) {
  const browserErrors = [];
  const networkErrors = [];
  const successfulApiPaths = new Set();
  const monitoredResourceTypes = new Set(["document", "script", "stylesheet", "font", "image", "xhr", "fetch"]);
  const fatalWarningPattern = /hydration|did not match|server-rendered html|chunkloaderror|loading chunk|next\.js.*error/i;
  const onConsole = (message) => {
    if (message.type() === "error" || (message.type() === "warning" && fatalWarningPattern.test(message.text()))) {
      const source = message.location().url;
      browserErrors.push(`console ${message.type()}: ${message.text()}${source ? ` (${source})` : ""}`);
    }
  };
  const onPageError = (error) => browserErrors.push(`pageerror: ${error.message}`);
  const onRequestFailed = (request) => {
    if (!monitoredResourceTypes.has(request.resourceType())) return;
    const failure = request.failure()?.errorText ?? "unknown";
    // App Router may cancel a superseded React Server Component prefetch.
    // Every other failed document, asset, XHR, or fetch remains fatal.
    if (isBenignAppRouterCancellation(request, failure)) return;
    networkErrors.push(`requestfailed ${request.resourceType()}: ${request.url()} (${failure})`);
  };
  const onResponse = (response) => {
    const request = response.request();
    if (!monitoredResourceTypes.has(request.resourceType())) return;
    const responseUrl = new URL(response.url());
    if (
      response.ok()
      && (responseUrl.pathname.startsWith("/v1/") || responseUrl.pathname === "/health" || responseUrl.pathname === "/version")
    ) {
      successfulApiPaths.add(responseUrl.pathname);
    }
    if (response.status() >= 400) {
      networkErrors.push(`HTTP ${response.status()} ${request.resourceType()}: ${response.url()}`);
    }
  };
  page.on("console", onConsole);
  page.on("pageerror", onPageError);
  page.on("requestfailed", onRequestFailed);
  page.on("response", onResponse);
  try {
    const responseWaits = (options.awaitResponses ?? []).map((predicate) =>
      page.waitForResponse(predicate, { timeout: 30_000 }),
    );
    let navigationResponse;
    if (responseWaits.length > 0) {
      [navigationResponse] = await Promise.all([
        page.goto(`${BASE_URL}${urlPath}`, { waitUntil: "domcontentloaded" }),
        ...responseWaits,
      ]);
    } else {
      navigationResponse = await page.goto(`${BASE_URL}${urlPath}`, { waitUntil: "domcontentloaded" });
    }
    if (!navigationResponse || !navigationResponse.ok()) {
      throw new Error(`Capture navigation failed for ${urlPath}: HTTP ${navigationResponse?.status() ?? "no response"}`);
    }
    await page.waitForLoadState("load");
    await page.waitForTimeout(urlPath.includes("capture=1") ? 1200 : 400);
    if (beforeShot) await beforeShot(page);
    if (urlPath.includes("capture=1")) {
      await page.locator("#demo-estate-watermark").waitFor({ state: "visible", timeout: 30_000 });
    }
    await page.evaluate(async () => {
      await document.fonts.ready;
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    const visibleText = await page.locator("body").innerText();
    const visibleErrorPatterns = [/500 Internal Server Error/i, /Application error/i, /Unhandled Runtime Error/i];
    const visibleError = visibleErrorPatterns.find((pattern) => pattern.test(visibleText));
    if (visibleError) throw new Error(`Visible error on ${urlPath}: ${visibleError}`);
    if (browserErrors.length > 0) {
      throw new Error(`Browser errors on ${urlPath}: ${browserErrors.join(" | ")}`);
    }
    if (networkErrors.length > 0) {
      throw new Error(`Network errors on ${urlPath}: ${networkErrors.join(" | ")}`);
    }
    for (const expected of options.expectedText ?? []) {
      const matched = expected instanceof RegExp ? expected.test(visibleText) : visibleText.includes(expected);
      if (!matched) throw new Error(`Expected content ${String(expected)} is missing on ${urlPath}`);
    }
    for (const rejected of options.rejectedText ?? []) {
      const matched = rejected instanceof RegExp ? rejected.test(visibleText) : visibleText.includes(rejected);
      if (matched) throw new Error(`Rejected content ${String(rejected)} is visible on ${urlPath}`);
    }
    if (options.assertNoHorizontalOverflow) {
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      );
      if (overflow) throw new Error(`Horizontal overflow is visible on ${urlPath}`);
    }
    for (const expectedPath of options.expectedApiPaths ?? []) {
      if (!successfulApiPaths.has(expectedPath)) {
        throw new Error(`Expected API response ${expectedPath} was not observed on ${urlPath}`);
      }
    }
    if (options.minGraphNodes) {
      const graphNodeCount = await page.locator(".react-flow__node:visible").count();
      const graphEdgeCount = await page.locator(".react-flow__edge").count();
      if (graphNodeCount < options.minGraphNodes || graphEdgeCount < (options.minGraphEdges ?? 1)) {
        throw new Error(`Incomplete graph on ${urlPath}: ${graphNodeCount} nodes / ${graphEdgeCount} edges`);
      }
    }
    if (!visibleText.includes(RELEASE_VERSION)) {
      throw new Error(`Release version ${RELEASE_VERSION} is not visible on ${urlPath}`);
    }
    if (options.readySelector) {
      // Recheck at the last possible moment. URL/state synchronization can
      // remount graph surfaces after their first ready signal.
      await page.locator(options.readySelector).first().waitFor({ state: "visible", timeout: 30_000 });
    }
    await page.screenshot({ path: path.join(captureOutputDir, filename), fullPage: false });
    console.log(`captured ${filename}`);
  } finally {
    page.off("console", onConsole);
    page.off("pageerror", onPageError);
    page.off("requestfailed", onRequestFailed);
    page.off("response", onResponse);
  }
}

async function writeScreenshotManifest(outputDir = IMAGE_DIR) {
  const screenshotEntries = [
    {
      path: "dashboard-live.png",
      page: "/?capture=1",
      scope: "Overview command center — posture grade, unique findings breakdown, scan coverage, and operational lanes",
      presentation: `${CAPTURE_THEME} desktop`,
    },
    {
      path: "dashboard-light-live.png",
      page: "/?capture=1",
      scope: "Overview command center in the light theme",
      presentation: "light desktop",
    },
    {
      path: "dashboard-mobile-live.png",
      page: "/?capture=1",
      scope: "Overview command center at a 390 by 844 viewport",
      presentation: "dark mobile",
    },
    {
      path: "dashboard-paths-live.png",
      page: "/?capture=1",
      scope: "Overview lower frame with unique exposure paths, recent scans, and activity",
    },
    {
      path: "cloud-accounts-live.png",
      page: "/connections?capture=1",
      scope: "Connections hub — scalable connector gallery across cloud, code, AI, and data sources",
    },
    {
      path: "new-scan-live.png",
      page: "/scan?capture=1",
      scope: "New Scan workspace with scope summary, read-only boundary, expected evidence, connected sources, and job navigation",
    },
    {
      path: "jobs-pipeline-live.png",
      page: "/jobs?capture=1",
      scope: "Completed job with six persisted stage events, measured wall clock, per-step durations, and activity",
    },
    {
      path: "agent-lifecycle-live.png",
      page: "/agents?name=developer-copilot&view=lifecycle&capture=1",
      scope: "Developer agent lifecycle across MCP servers, package, tool, credential name, and synthetic finding",
    },
    {
      path: "mesh-live.png",
      page: "/graph?lens=mesh&capture=1",
      scope: "Multi-agent mesh with shared filesystem MCP, labeled edges, and both IDE + SRE agents in scope",
    },
    {
      path: "gateway-policies-live.png",
      page: "/runtime?tab=gateway&capture=1",
      scope: "Runtime gateway KPI rollup, enforcement posture, and recent tool-call evidence",
    },
    {
      path: "security-graph-live.png",
      page: `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`,
      scope: "Prioritized attack path with graph evidence export and remediation handoff",
      presentation: `${CAPTURE_THEME} desktop`,
    },
    {
      path: "correlation-receipts-live.png",
      page: `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&correlation=1&capture=1`,
      scope: "Reference evidence lab source receipts flowing into one immutable, manifest-bound correlated snapshot",
      presentation: `${CAPTURE_THEME} desktop`,
      evidence_artifact: path.relative(REPO_ROOT, REFERENCE_LAB_PROOF_PATH),
      evidence_sha256: referenceLabActualDigest,
      correlation_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
    },
    {
      path: "correlation-path-live.png",
      page: `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&cve=CVE-2023-4863&capture=1`,
      scope: "Reference evidence lab confirmed path with exact OCI digest, advisory, hop provenance, freshness, runtime observation, strict block proof, and remediation handoff",
      presentation: `${CAPTURE_THEME} desktop`,
      evidence_artifact: path.relative(REPO_ROOT, REFERENCE_LAB_PROOF_PATH),
      evidence_sha256: referenceLabActualDigest,
      correlation_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
    },
    {
      path: "correlation-receipts-light-live.png",
      page: `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&correlation=1&capture=1`,
      scope: "Reference evidence lab automatic journey and manifest-bound source receipts in the light theme",
      presentation: "light desktop",
      evidence_artifact: path.relative(REPO_ROOT, REFERENCE_LAB_PROOF_PATH),
      evidence_sha256: referenceLabActualDigest,
      correlation_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
    },
    {
      path: "correlation-path-light-live.png",
      page: `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&cve=CVE-2023-4863&capture=1`,
      scope: "Reference evidence lab confirmed path and hop receipts in the light theme",
      presentation: "light desktop",
      evidence_artifact: path.relative(REPO_ROOT, REFERENCE_LAB_PROOF_PATH),
      evidence_sha256: referenceLabActualDigest,
      correlation_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
    },
    {
      path: "correlation-receipts-mobile-live.png",
      page: `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&correlation=1&capture=1`,
      scope: "Reference evidence lab automatic journey and manifest-bound source receipts at a 390 by 844 viewport",
      presentation: "dark mobile",
      evidence_artifact: path.relative(REPO_ROOT, REFERENCE_LAB_PROOF_PATH),
      evidence_sha256: referenceLabActualDigest,
      correlation_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
    },
    {
      path: "correlation-path-mobile-live.png",
      page: `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&cve=CVE-2023-4863&capture=1`,
      scope: "Reference evidence lab confirmed path and hop receipts at a 390 by 844 viewport",
      presentation: "dark mobile",
      evidence_artifact: path.relative(REPO_ROOT, REFERENCE_LAB_PROOF_PATH),
      evidence_sha256: referenceLabActualDigest,
      correlation_manifest_sha256: REFERENCE_LAB.correlation.manifest_sha256,
    },
    {
      path: "security-graph-light-live.png",
      page: `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`,
      scope: "Prioritized attack path in the light theme",
      presentation: "light desktop",
    },
    {
      path: "security-graph-mobile-live.png",
      page: `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`,
      scope: "Prioritized attack path at a 390 by 844 viewport",
      presentation: "dark mobile",
    },
    {
      path: "investigation-canvas-current-1512x811.png",
      page: "/security-graph?lens=estate&rollup=1&capture=1",
      scope: "Observed current-state Investigation Canvas at the audited 1512 by 811 viewport",
      presentation: "dark desktop 1512x811",
    },
    {
      path: "investigation-canvas-proposed-1568x780.png",
      page: `/security-graph?lens=estate&rollup=1&scenario=${SCENARIO_ID}&state=proposed&capture=1`,
      scope: "Clearly modeled proposed-state comparison at the audited 1568 by 780 viewport",
      presentation: "light desktop 1568x780",
    },
    {
      path: "lineage-graph-live.png",
      page: `/graph?capture=1&scan=${SCAN_ID}&agent=developer-copilot&vulnOnly=1`,
      scope: "URL-pinned developer-copilot vulnerable-path lineage across agent, MCP, package, and finding nodes",
    },
    {
      path: "context-map-live.png",
      page: "/graph?lens=context&capture=1",
      scope: "Context map with path focus off — tools, credentials, servers, and lateral agent links (not CVE-only)",
    },
    {
      path: "inventory-live.png",
      page: "/inventory?capture=1",
      scope: "Unified asset-kind roll-up across discovered packages, MCP servers, agents, cloud, identities, containers, and code",
    },
    {
      path: "fleet-state-live.png",
      page: "/fleet?capture=1",
      scope: "Expanded quarantined fleet row showing lifecycle distribution, owner metadata, environment label, and enforcement state",
    },
    {
      path: "identity-audit-live.png",
      page: "/audit?capture=1",
      scope: "Audit log filtered to identity resources with issue, rotate, and revoke events",
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
    {
      path: "remediation-light-live.png",
      page: "/remediation?capture=1",
      scope: "Fix-first remediation workflow in the light theme",
      presentation: "light desktop",
    },
    {
      path: "remediation-mobile-live.png",
      page: "/remediation?capture=1",
      scope: "Fix-first remediation workflow at a 390 by 844 viewport",
      presentation: "dark mobile",
    },
  ];
  const screenshots = await Promise.all(
    screenshotEntries.map(async (entry) => ({
      presentation: `${CAPTURE_THEME} desktop`,
      ...entry,
      visible_version: RELEASE_VERSION,
      sha256: await screenshotSha256(path.join(outputDir, entry.path)),
    })),
  );
  const provenance = await captureSourceProvenance();
  const manifest = {
    release_version: RELEASE_VERSION,
    captured_at: new Date().toISOString(),
    ...provenance,
    capture_note:
      "Deterministically captured from real Next.js dashboard routes in capture mode. The two correlation hero views consume the committed, hash-pinned Reference evidence lab — modeled local infrastructure artifact with CVE-2023-4863 and exact canonical joins. Remaining gallery fixtures are explicitly synthetic UI states. No external, customer, or private infrastructure data is used.",
    screenshots,
  };
  await fs.writeFile(path.join(outputDir, path.basename(SCREENSHOT_MANIFEST)), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`updated ${path.relative(REPO_ROOT, SCREENSHOT_MANIFEST)}`);
}

async function scrollTo(page, y) {
  await page.evaluate((targetY) => window.scrollTo({ top: targetY, behavior: "instant" }), y);
  await page.waitForTimeout(350);
}

async function fitReactFlow(page, { timeout = 30_000 } = {}) {
  await page.waitForSelector(".react-flow", { state: "attached", timeout });
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
  const stageDir = await fs.mkdtemp(path.join(os.tmpdir(), "agent-bom-product-proof-"));
  captureOutputDir = stageDir;
  const server = await startServerIfNeeded();
  let browser;
  try {
    await waitForServer(BASE_URL);
    browser = await chromium.launch();
    const newCapturePage = async (theme, viewport) => {
      const capturePage = await browser.newPage({ viewport, deviceScaleFactor: 1 });
      await installRoutes(capturePage);
      await capturePage.addInitScript((selectedTheme) => {
        window.localStorage.setItem("agent-bom-theme", selectedTheme);
      }, theme);
      return capturePage;
    };
    const prepareCorrelationReceipts = async (proofPage) => {
      await proofPage.getByRole("button", { name: /^Evidence scope Current scan/i }).click();
      const workflow = proofPage.getByTestId("graph-correlation-workflow");
      await workflow.waitFor({ state: "visible", timeout: 30_000 });
      await proofPage.getByTestId("graph-correlation-receipt-dag").waitFor({ state: "visible", timeout: 30_000 });
      // Give the viewport enough trailing room to place Evidence scope just
      // below the fixed product header. Without this capture-only spacer the
      // browser hits the document's maximum scroll position and leaves the
      // previous path card in the hero frame.
      await proofPage.evaluate(() => {
        document.body.style.paddingBottom = "900px";
      });
      const workflowTop = await workflow.evaluate(
        (element) => element.getBoundingClientRect().top + window.scrollY,
      );
      await proofPage.evaluate((workflowTop) => {
        window.scrollTo({ top: workflowTop - 88, behavior: "instant" });
      }, workflowTop);
      await proofPage.waitForTimeout(500);
    };
    const prepareCorrelationPath = async (proofPage) => {
      const proof = proofPage.getByTestId("attack-path-correlation-proof");
      await proof.waitFor({ state: "visible", timeout: 30_000 });
      const selectedPath = proofPage.getByTestId("selected-exposure-path");
      await selectedPath.scrollIntoViewIfNeeded();
      const topOffset = (proofPage.viewportSize()?.width ?? 1440) < 640 ? -72 : -300;
      await proofPage.evaluate((offset) => window.scrollBy({ top: offset, behavior: "instant" }), topOffset);
      await proofPage.waitForTimeout(500);
    };
    const correlationReceiptAssertions = {
      expectedText: [
        "Evidence journey",
        "Evidence correlation complete",
        "Image + SBOM",
        "Runtime",
        "1 confirmed attack path",
      ],
      expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph/correlations"],
      readySelector: '[data-testid="graph-correlation-receipt-dag"]',
    };
    const correlationPathAssertions = {
      expectedText: [
        "CVE-2023-4863",
        REFERENCE_LAB.container_digest,
        "Path verified",
        "Runtime observed",
        "Runtime block verified",
        "Patch Pillow and re-run correlation",
      ],
      expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph/views/fix-first", "/v1/graph/attack-paths"],
      readySelector: '[data-testid="attack-path-correlation-proof"]',
    };
    const page = await newCapturePage(CAPTURE_THEME, { width: 1440, height: 980 });

    await capture(page, "/?capture=1", "dashboard-live.png", undefined, {
      expectedText: [/Overview/i, /Risk posture/i, /15 unique open CVEs/i],
      expectedApiPaths: ["/v1/posture/counts", "/v1/overview"],
    });
    await capture(page, "/?capture=1", "dashboard-paths-live.png", async (dashboardPage) => {
      await scrollTo(dashboardPage, 720);
    }, {
      expectedText: ["Top risks", "Recent scans", "Activity", "DEMO-VULN-21441"],
      expectedApiPaths: ["/v1/overview", "/v1/jobs"],
    });
    await capture(page, "/connections?capture=1", "cloud-accounts-live.png", async (connectionsPage) => {
      await connectionsPage.getByRole("heading", { name: "Connections", exact: true }).waitFor({ state: "visible", timeout: 10_000 });
      const galleryHeading = connectionsPage.getByText("Connect a source", { exact: true }).last();
      await galleryHeading.scrollIntoViewIfNeeded();
      await connectionsPage.evaluate(() => window.scrollBy({ top: -120, behavior: "instant" }));
    }, {
      expectedText: ["Connections", "Amazon Web Services", "Microsoft Azure", "Repositories"],
      expectedApiPaths: ["/v1/cloud/connections", "/v1/sources", "/v1/connectors"],
    });
    await capture(page, "/scan?capture=1", "new-scan-live.png", async (scanPage) => {
      await scanPage.getByRole("heading", { name: /New Scan|Run scan/i }).first().waitFor({ state: "visible", timeout: 10_000 });
    }, {
      expectedText: ["New Scan", "What this scan collects and produces", "Read-only boundary", /Scope now/i, /Scan jobs/i],
      expectedApiPaths: ["/v1/cloud/connections", "/v1/sources"],
    });
    await capture(page, "/jobs?capture=1", "jobs-pipeline-live.png", async (jobsPage) => {
      await jobsPage.getByTestId(`job-pipeline-${SCAN_ID}`).waitFor({ state: "visible", timeout: 20_000 });
      await jobsPage.getByText("Timing & activity", { exact: true }).scrollIntoViewIfNeeded();
      await jobsPage.evaluate(() => window.scrollBy({ top: -540, behavior: "instant" }));
    }, {
      expectedText: [/scan pipeline dag/i, /6\/6 stages complete/i, /wall clock 2m 0s/i, /timing & activity/i, "12.0s"],
      rejectedText: [/Loading jobs/i, /Loading persisted pipeline events/i, /Stage telemetry unavailable/i],
      expectedApiPaths: ["/v1/jobs", `/v1/scan/${SCAN_ID}`],
      minGraphNodes: 6,
      minGraphEdges: 5,
    });
    await capture(page, "/agents?name=developer-copilot&view=lifecycle&capture=1", "agent-lifecycle-live.png", async (agentsPage) => {
      await agentsPage.getByText("Lifecycle Graph", { exact: true }).waitFor({ state: "visible", timeout: 20_000 });
      await fitReactFlow(agentsPage);
      await scrollTo(agentsPage, 0);
    }, {
      expectedText: ["Lifecycle Graph", "developer-copilot", "github-enterprise MCP", "create_pull_request", "DEMO-VULN-21441"],
      rejectedText: [/Loading/i],
      expectedApiPaths: ["/v1/agents/developer-copilot/lifecycle"],
      minGraphNodes: 7,
      minGraphEdges: 6,
    });
    await page.setViewportSize({ width: 1440, height: 1120 });
    await capture(page, "/graph?lens=mesh&capture=1", "mesh-live.png", async (meshPage) => {
      // ReactFlow can preserve a hidden, pre-measurement node tree across an
      // App Router transition. A hard reload gives the capture a fresh canvas
      // and makes the readiness assertion deterministic in both themes.
      await meshPage.reload({ waitUntil: "load" });
      await meshPage
        .locator(".react-flow__node:visible")
        .filter({ hasText: "filesystem MCP" })
        .first()
        .waitFor({ state: "visible", timeout: 30_000 });
      await meshPage
        .locator(".react-flow__node:visible")
        .filter({ hasText: "sre-runbook-agent" })
        .first()
        .waitFor({ state: "visible", timeout: 30_000 });
      const showAll = meshPage.getByRole("button", { name: "Show all", exact: true });
      if (await showAll.count()) {
        await showAll.click();
        await meshPage.waitForTimeout(800);
      }
      await fitReactFlow(meshPage);
      await meshPage.waitForTimeout(500);
      await scrollTo(meshPage, 0);
    }, {
      expectedText: [
        "Agent Mesh",
        "developer-copilot",
        "sre-runbook-agent",
        "filesystem MCP",
        "Uses",
      ],
      expectedApiPaths: ["/v1/jobs", `/v1/scan/${SCAN_ID}`],
      minGraphNodes: 4,
      minGraphEdges: 3,
    });
    await page.setViewportSize({ width: 1440, height: 980 });
    await capture(page, `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`, "security-graph-live.png", async (securityGraphPage) => {
      await securityGraphPage
        .getByRole("img", { name: /Selected exposure path graph for/i })
        .waitFor({ state: "visible", timeout: 30_000 });
    }, {
      expectedText: ["Investigation", "Contractor Reviewer", "Developer Copilot", "DEMO-VULN-21441"],
      expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph/views/fix-first"],
      readySelector: 'section[aria-label="Selected exposure path graph"]',
    });
    const correlationPage = await newCapturePage("dark", { width: 1440, height: 820 });
    await capture(
      correlationPage,
      `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&correlation=1&capture=1`,
      "correlation-receipts-live.png",
      prepareCorrelationReceipts,
      correlationReceiptAssertions,
    );
    await correlationPage.close();

    await page.setViewportSize({ width: 1440, height: 1120 });
    await capture(
      page,
      `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&cve=CVE-2023-4863&capture=1`,
      "correlation-path-live.png",
      prepareCorrelationPath,
      correlationPathAssertions,
    );
    await page.setViewportSize({ width: 1440, height: 980 });
    const currentCanvasPage = await newCapturePage("dark", { width: 1512, height: 811 });
    await capture(
      currentCanvasPage,
      "/security-graph?lens=estate&rollup=1&capture=1",
      "investigation-canvas-current-1512x811.png",
      async (canvasPage) => {
        await canvasPage.waitForLoadState("networkidle");
        await canvasPage.getByRole("heading", { name: "Investigation Canvas" }).waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.locator('[data-testid="graph-rollup-decision-surface"]').waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.locator('[data-testid="graph-rollup-relationship-completeness"]').waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.locator('[data-testid="graph-rollup-card-grid"] article').first().waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.waitForTimeout(500);
        await canvasPage.locator('[data-testid="graph-rollup-decision-surface"]').waitFor({
          state: "visible",
          timeout: 30_000,
        });
      },
      {
        awaitResponses: [
          (response) => new URL(response.url()).pathname === "/v1/graph/rollup" && response.ok(),
        ],
        expectedText: ["Investigation Canvas", "Risk-prioritized scopes", "aggregated relationship rows"],
        expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph/rollup", "/v1/graph/scenarios"],
        readySelector: '[data-testid="graph-rollup-decision-surface"]',
        assertNoHorizontalOverflow: true,
      },
    );
    await currentCanvasPage.close();

    const proposedCanvasPage = await newCapturePage("light", { width: 1568, height: 780 });
    await capture(
      proposedCanvasPage,
      `/security-graph?lens=estate&rollup=1&scenario=${SCENARIO_ID}&state=proposed&capture=1`,
      "investigation-canvas-proposed-1568x780.png",
      async (canvasPage) => {
        await canvasPage.waitForLoadState("networkidle");
        await canvasPage.getByText("Proposed scenario — not observed or deployed", { exact: false }).waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.getByText("Current · observed", { exact: true }).waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.getByText("Proposed · modeled", { exact: true }).waitFor({
          state: "visible",
          timeout: 30_000,
        });
        await canvasPage.locator(".react-flow__node:visible").first().waitFor({
          state: "visible",
          timeout: 30_000,
        });
      },
      {
        awaitResponses: [
          (response) =>
            new URL(response.url()).pathname === `/v1/graph/scenarios/${SCENARIO_ID}/comparison` &&
            response.ok(),
        ],
        expectedText: [
          "Investigation Canvas",
        ],
        expectedApiPaths: [
          "/v1/graph/snapshots",
          "/v1/graph/scenarios",
          `/v1/graph/scenarios/${SCENARIO_ID}/comparison`,
        ],
        readySelector:
          'section[aria-label="Scenario comparison"]:has-text("Proposed scenario — not observed or deployed"):has-text("Current · observed"):has-text("Proposed · modeled")',
        minGraphNodes: 3,
        minGraphEdges: 1,
        assertNoHorizontalOverflow: true,
      },
    );
    await proposedCanvasPage.close();
    await capture(page, `/graph?capture=1&scan=${SCAN_ID}&agent=developer-copilot&vulnOnly=1`, "lineage-graph-live.png", async (lineagePage) => {
      await lineagePage.getByRole("heading", { name: "Lineage Graph" }).waitFor({
        state: "visible",
        timeout: 10_000,
      });
      await lineagePage.locator(".react-flow__node:visible").first().waitFor({ state: "visible", timeout: 10_000 });
      await fitReactFlow(lineagePage);
      await lineagePage.locator(".react-flow__controls-zoomout").first().click({ force: true });
      await scrollTo(lineagePage, 140);
      await lineagePage.waitForTimeout(350);
    }, {
      expectedText: [
        "Relevant paths",
        "Developer Copilot",
        "github-enterprise MCP",
        "next@",
        "DEMO-VULN-21441",
      ],
      expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph"],
      minGraphNodes: 4,
      minGraphEdges: 3,
    });
    await capture(
      page,
      "/graph?lens=context&capture=1",
      "context-map-live.png",
      async (contextPage) => {
        await contextPage.getByRole("heading", { name: "Context Map" }).waitFor({
          state: "visible",
          timeout: 30_000,
        });
        const agentScope = contextPage.locator("select").first();
        if ((await agentScope.count()) > 0) {
          await agentScope.selectOption("developer-copilot");
          await contextPage.waitForTimeout(600);
        }
        const showAll = contextPage.getByRole("button", { name: "Show all", exact: true });
        if (await showAll.count()) {
          await showAll.click();
          await contextPage.waitForTimeout(400);
        }
        await contextPage.locator(".react-flow__node").first().waitFor({
          state: "visible",
          timeout: 20_000,
        });
        await fitReactFlow(contextPage);
        // One extra zoom for README proof — small context chains stay width-bound
        // after fitView and read small in a tall pane without it.
        const zoomIn = contextPage.locator(".react-flow__controls-zoomin").first();
        if (await zoomIn.count()) {
          await zoomIn.click({ force: true });
          await contextPage.waitForTimeout(200);
        }
        await scrollTo(contextPage, 0);
      },
      {
        awaitResponses: [(response) => response.url().includes("/context-graph") && response.ok()],
        expectedText: [
          "Context Map",
          "developer-copilot",
          "create_pull_request",
          "DEMO_CRED_REF",
        ],
        expectedApiPaths: ["/v1/jobs", `/v1/scan/${SCAN_ID}`, `/v1/scan/${SCAN_ID}/context-graph`],
        minGraphNodes: 4,
        minGraphEdges: 3,
      },
    );
    await page.setViewportSize({ width: 1440, height: 980 });
    await capture(page, "/inventory?capture=1", "inventory-live.png", async (inventoryPage) => {
      await inventoryPage.getByRole("heading", { name: "Asset inventory" }).waitFor({
        state: "visible",
        timeout: 10_000,
      });
      await scrollTo(inventoryPage, 0);
    }, {
      expectedText: ["Asset inventory", "Packages", "MCP servers", "AI agents", "Cloud resources", "Coverage reflects only what has actually been scanned or connected"],
      expectedApiPaths: ["/v1/inventory/summary", "/v1/inventory/assets"],
    });
    await capture(page, "/fleet?capture=1", "fleet-state-live.png", async (fleetPage) => {
      await fleetPage.getByText("developer-copilot").first().click({ force: true });
      const enforcementAction = fleetPage.getByText("Re-enforce gateway deny").first();
      await enforcementAction.waitFor({ state: "visible", timeout: 8_000 });
      await enforcementAction.evaluate((element) => element.scrollIntoView({ block: "center", behavior: "instant" }));
      await fleetPage.waitForTimeout(350);
    }, {
      expectedText: ["Lifecycle Distribution", "developer-copilot", "Quarantined", "Re-enforce gateway deny"],
      expectedApiPaths: ["/v1/fleet", "/v1/fleet/stats"],
    });
    await capture(page, "/runtime?tab=gateway&capture=1", "gateway-policies-live.png", async (gatewayPage) => {
      await gatewayPage.getByText("Calls today").first().waitFor({ state: "visible", timeout: 8000 });
      await gatewayPage.getByText("Gateway activity").first().waitFor({ state: "visible", timeout: 8000 });
      await scrollTo(gatewayPage, 0);
    }, {
      expectedText: ["Calls today", "4,485", "Gateway activity", "developer-copilot", "Repo-write blocked"],
      expectedApiPaths: ["/v1/gateway/policies", "/v1/gateway/feed", "/v1/gateway/feed/kpis"],
    });
    await page.setViewportSize({ width: 1440, height: 1120 });
    await capture(page, "/audit?capture=1", "identity-audit-live.png", async (auditPage) => {
      const filteredResponse = auditPage.waitForResponse((response) => {
        const url = new URL(response.url());
        return url.pathname === "/v1/audit" && url.searchParams.get("resource") === "identity" && response.ok();
      });
      const resourceFilter = auditPage.getByPlaceholder("Filter by resource…");
      await resourceFilter.fill("identity");
      await filteredResponse;
      const issuedEvent = auditPage.getByText("agent_identity.issued");
      await issuedEvent.waitFor({ state: "visible", timeout: 8_000 });
      await issuedEvent.evaluate((element) => element.scrollIntoView({ block: "center", behavior: "instant" }));
      await auditPage.waitForTimeout(350);
    }, {
      expectedText: ["agent_identity.issued", "agent_identity.rotated", "agent_identity.revoked", "identity/id_89c1a6f406bd7189"],
      rejectedText: ["scan.completed", "gateway.policy.denied", "compliance.bundle.signed"],
      expectedApiPaths: ["/v1/audit", "/v1/audit/integrity"],
    });
    await page.setViewportSize({ width: 1440, height: 980 });
    await capture(page, "/findings?capture=1", "dependency-map-live.png", async (findingsPage) => {
      await findingsPage.getByRole("heading", { name: /Findings|Issues|Vulnerabilit/i }).first().waitFor({
        state: "visible",
        timeout: 10_000,
      }).catch(async () => {
        await findingsPage.getByText(/CVE|critical|high|package/i).first().waitFor({ state: "visible", timeout: 8_000 });
      });
      await scrollTo(findingsPage, 0);
    }, {
      expectedText: ["Findings queue", "15 issues", "DEMO-VULN-21441", "DEMO-VULN-77881"],
      expectedApiPaths: ["/v1/findings", "/v1/findings/triage"],
      rejectedText: ["17 findings"],
    });
    await capture(page, "/remediation?capture=1", "remediation-live.png", undefined, {
      expectedText: ["Package remediation plan", "next", "16.2.7", "DEMO-VULN-21441", "Campaign workflow and verification"],
      rejectedText: ["42.5% modeled window risk"],
      expectedApiPaths: ["/v1/campaigns", "/v1/campaigns/verification-queue"],
    });

    const lightPage = await newCapturePage("light", { width: 1440, height: 980 });
    await capture(lightPage, "/?capture=1", "dashboard-light-live.png", undefined, {
      expectedText: [/Overview/i, /Risk posture/i, /15 unique open CVEs/i],
      expectedApiPaths: ["/v1/posture/counts", "/v1/overview"],
    });
    await capture(
      lightPage,
      `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&correlation=1&capture=1`,
      "correlation-receipts-light-live.png",
      prepareCorrelationReceipts,
      correlationReceiptAssertions,
    );
    await capture(
      lightPage,
      `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&cve=CVE-2023-4863&capture=1`,
      "correlation-path-light-live.png",
      prepareCorrelationPath,
      correlationPathAssertions,
    );
    await capture(lightPage, `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`, "security-graph-light-live.png", async (securityGraphPage) => {
      await securityGraphPage
        .getByRole("img", { name: /Selected exposure path graph for/i })
        .waitFor({ state: "visible", timeout: 30_000 });
      await scrollTo(securityGraphPage, 0);
    }, {
      expectedText: ["Investigation", "Contractor Reviewer", "Developer Copilot", "DEMO-VULN-21441"],
      expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph/views/fix-first"],
      readySelector: 'section[aria-label="Selected exposure path graph"]',
    });
    await capture(lightPage, "/remediation?capture=1", "remediation-light-live.png", undefined, {
      expectedText: ["Package remediation plan", "next", "16.2.7", "DEMO-VULN-21441", "Campaign workflow and verification"],
      rejectedText: [/Loading prioritized campaigns/i, "42.5% modeled window risk"],
      expectedApiPaths: ["/v1/campaigns", "/v1/campaigns/verification-queue"],
    });

    const mobilePage = await newCapturePage("dark", { width: 390, height: 844 });
    await capture(mobilePage, "/?capture=1", "dashboard-mobile-live.png", undefined, {
      expectedText: [/Overview/i, /Risk posture/i, /15 unique open CVEs/i],
      expectedApiPaths: ["/v1/posture/counts", "/v1/overview"],
    });
    await capture(
      mobilePage,
      `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&correlation=1&capture=1`,
      "correlation-receipts-mobile-live.png",
      prepareCorrelationReceipts,
      { ...correlationReceiptAssertions, assertNoHorizontalOverflow: true },
    );
    await capture(
      mobilePage,
      `/security-graph?lens=attack-path&scan=${REFERENCE_CORRELATION_ID}&cve=CVE-2023-4863&capture=1`,
      "correlation-path-mobile-live.png",
      prepareCorrelationPath,
      { ...correlationPathAssertions, assertNoHorizontalOverflow: true },
    );
    await capture(mobilePage, `/security-graph?lens=attack-path&scan=${SCAN_ID}&capture=1`, "security-graph-mobile-live.png", async (securityGraphPage) => {
      await securityGraphPage
        .getByTestId("exposure-path-mobile-sequence")
        .waitFor({ state: "visible", timeout: 30_000 });
      await scrollTo(securityGraphPage, 0);
    }, {
      expectedText: ["Investigation", "Contractor Reviewer", "Developer Copilot", "DEMO-VULN-21441"],
      expectedApiPaths: ["/v1/graph/snapshots", "/v1/graph/views/fix-first"],
      readySelector: '[data-testid="exposure-path-mobile-sequence"]',
      rejectedText: [/Loading/i],
      assertNoHorizontalOverflow: true,
    });
    await capture(mobilePage, "/remediation?capture=1", "remediation-mobile-live.png", undefined, {
      expectedText: ["Package remediation plan", "next", "16.2.7", "Campaign workflow and verification"],
      rejectedText: [/Loading prioritized campaigns/i, "42.5% modeled window risk"],
      expectedApiPaths: ["/v1/campaigns", "/v1/campaigns/verification-queue"],
      assertNoHorizontalOverflow: true,
    });
    await writeScreenshotManifest(stageDir);
    for (const artifact of await fs.readdir(stageDir)) {
      await fs.copyFile(path.join(stageDir, artifact), path.join(IMAGE_DIR, artifact));
    }
  } finally {
    await browser?.close();
    await stopServer(server);
    await fs.rm(stageDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
