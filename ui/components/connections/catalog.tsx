"use client";

import {
  type CloudConnectionRecord,
  type SourceKind
} from "@/lib/api";
import {
  type SourceCategory
} from "@/lib/connections-sources";
import {
  Activity,
  Bot,
  Cloud,
  Container,
  FileCode,
  GitBranch,
  Plug,
  Radio,
  Shield,
  Workflow
} from "lucide-react";



// ── Hub tabs ────────────────────────────────────────────────────────────────
// One Connections hub with URL-synced segments: Connect (add any source —
// cloud account, repo, image, IaC, MCP, warehouse, or a coding agent) and
// Sources (one dense, filterable table of everything registered — cloud
// connections + registered sources merged and deduped). Retires the separate
// `/sources` route (kept as a redirect).

export type HubTab = "connect" | "sources" | "endpoints";


export function parseTab(value: string | null, established: boolean): HubTab {
  if (value === "sources" || value === "connect" || value === "endpoints") return value;
  return established ? "sources" : "connect";
}


// ── Provider catalog ──────────────────────────────────────────────────────────
// Every option maps its wizard fields onto the connection's role_ref (plaintext
// principal ref), external_id (the one write-only secret), and auth_params
// (non-secret provider params). `permissions` / `cli` mirror the real
// `agent-bom connect <provider>` onboarding (src/agent_bom/cli/_entry_points.py).

export type ProviderReadiness = "live";


export interface ProviderField {
  key: string;
  label: string;
  placeholder: string;
  mono?: boolean;
}


export interface ProviderOption {
  value: string;
  label: string;
  tagline: string;
  permissions: string;
  cli: string;
  readiness: ProviderReadiness;
  roleField: ProviderField;
  authFields: ProviderField[];
  secretField: ProviderField & { multiline?: boolean; hint: string };
  usesRegions: boolean;
  setupSteps: string[];
}


export const PROVIDER_OPTIONS: ProviderOption[] = [
  {
    value: "aws",
    label: "Amazon Web Services",
    tagline: "Read-only AssumeRole",
    permissions: "IAM SecurityAudit / ViewOnly role (read-only)",
    cli: "agent-bom connect aws",
    readiness: "live",
    roleField: {
      key: "role_ref",
      label: "Read-only role ARN",
      placeholder: "arn:aws:iam::123456789012:role/agent-bom-readonly",
      mono: true,
    },
    authFields: [],
    secretField: {
      key: "external_id",
      label: "External ID",
      placeholder: "••••••••••••",
      hint: "The ExternalId from the role's trust policy. Stored encrypted, never shown again.",
    },
    usesRegions: true,
    setupSteps: [
      "Create an IAM role with a trust policy that allows the agent-bom control plane to assume it.",
      "Require an ExternalId on the trust policy and keep it secret.",
      "Attach AWS-managed ReadOnlyAccess (or SecurityAudit).",
      "Copy the role ARN and the ExternalId into the next step.",
    ],
  },
  {
    value: "azure",
    label: "Microsoft Azure",
    tagline: "Read-only Reader credential",
    permissions: "Reader-role service principal (read-only)",
    cli: "agent-bom connect azure",
    readiness: "live",
    roleField: {
      key: "role_ref",
      label: "Client ID (app registration)",
      placeholder: "00000000-0000-0000-0000-000000000000",
      mono: true,
    },
    authFields: [
      {
        key: "tenant_id",
        label: "Tenant ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        mono: true,
      },
      {
        key: "subscription_id",
        label: "Subscription ID",
        placeholder: "00000000-0000-0000-0000-000000000000",
        mono: true,
      },
    ],
    secretField: {
      key: "external_id",
      label: "Client secret",
      placeholder: "••••••••••••",
      hint: "The app registration's client secret. Stored encrypted, never shown again.",
    },
    usesRegions: false,
    setupSteps: [
      "Register an app (service principal) in Microsoft Entra ID and create a client secret.",
      "Grant the app the built-in Reader role on the subscription (read-only).",
      "Copy the Tenant ID, Subscription ID, and Client ID into the next step.",
      "Paste the client secret — it is stored encrypted and never displayed again.",
    ],
  },
  {
    value: "gcp",
    label: "Google Cloud",
    tagline: "Read-only service account",
    permissions: "roles/viewer service account (read-only)",
    cli: "agent-bom connect gcp",
    readiness: "live",
    roleField: {
      key: "role_ref",
      label: "Service account email",
      placeholder: "agent-bom@project.iam.gserviceaccount.com",
      mono: true,
    },
    authFields: [
      {
        key: "project_id",
        label: "Project ID",
        placeholder: "my-project-123",
        mono: true,
      },
    ],
    secretField: {
      key: "external_id",
      label: "Service account key (JSON)",
      placeholder: "Paste the service-account key JSON",
      multiline: true,
      hint: "The service-account key JSON. Brokered with the cloud-platform.read-only scope. Stored encrypted, never shown again.",
    },
    usesRegions: false,
    setupSteps: [
      "Create a service account in the target project and grant it the read-only Viewer role.",
      "Create a JSON key for the service account.",
      "Copy the Project ID and the service-account email into the next step.",
      "Paste the key JSON — it is stored encrypted and never displayed again.",
    ],
  },
  {
    value: "snowflake",
    label: "Snowflake",
    tagline: "Read-only account connection",
    permissions: "Read-only governance access",
    cli: "agent-bom connect snowflake",
    readiness: "live",
    roleField: {
      key: "role_ref",
      label: "Account",
      placeholder: "ORG-ACCOUNT",
      mono: true,
    },
    authFields: [
      { key: "user", label: "User", placeholder: "ABOM_SVC", mono: true },
      { key: "role", label: "Role", placeholder: "ABOM_READONLY", mono: true },
      {
        key: "warehouse",
        label: "Warehouse",
        placeholder: "ABOM_WH",
        mono: true,
      },
    ],
    secretField: {
      key: "external_id",
      label: "Private key (PEM)",
      placeholder: "Paste the PKCS#8 PEM private key…",
      multiline: true,
      hint: "The RSA private key (PEM) for key-pair auth. Stored encrypted, never shown again.",
    },
    usesRegions: false,
    setupSteps: [
      "Create a read-only role and a service user with key-pair authentication.",
      "Assign the read-only role and a warehouse the user can use.",
      "Copy the Account, User, Role, and Warehouse into the next step.",
      "Paste the private key (PEM) — it is stored encrypted and never displayed again.",
    ],
  },
];


export function providerOption(value: string): ProviderOption | undefined {
  return PROVIDER_OPTIONS.find((option) => option.value === value);
}


export function providerLabel(value: string): string {
  return providerOption(value)?.label ?? value.toUpperCase();
}


export const SCANNABLE_PROVIDERS = new Set(PROVIDER_OPTIONS.map((option) => option.value));


// ── Source registration catalog ───────────────────────────────────────────────

export type IngestMode =
  | "Direct scan"
  | "Read-only connector"
  | "Pushed ingest"
  | "Runtime"
  | "Imported artifact";


export interface KindOption {
  value: SourceKind;
  label: string;
  mode: IngestMode;
  detail: string;
}


export const SOURCE_KIND_OPTIONS: KindOption[] = [
  {
    value: "scan.repo",
    label: "Repo / package scan",
    mode: "Direct scan",
    detail: "Trigger repo, package, or SBOM-oriented discovery jobs through the control plane.",
  },
  {
    value: "scan.image",
    label: "Container / image scan",
    mode: "Direct scan",
    detail: "Run image and package analysis as a queued scan job instead of from the browser.",
  },
  {
    value: "scan.iac",
    label: "IaC / cluster scan",
    mode: "Direct scan",
    detail: "Schedule Terraform, Kubernetes, and infrastructure posture scans.",
  },
  {
    value: "scan.cloud",
    label: "Cloud account scan",
    mode: "Direct scan",
    detail: "Launch cloud discovery through backend-owned jobs and read-only account access.",
  },
  {
    value: "scan.mcp_config",
    label: "MCP configuration scan",
    mode: "Direct scan",
    detail: "Discover MCP servers, tools, and agent config entry points from inventory sources.",
  },
  {
    value: "connector.cloud_read_only",
    label: "SaaS connector",
    mode: "Read-only connector",
    detail: "Run one installed named connector using credentials configured on the self-hosted control plane.",
  },
  {
    value: "ingest.fleet_sync",
    label: "Fleet sync",
    mode: "Pushed ingest",
    detail: "Accept fleet inventory from authenticated push routes instead of direct browser collection.",
  },
  {
    value: "ingest.trace_push",
    label: "Trace ingest",
    mode: "Pushed ingest",
    detail: "Receive OTLP-style traces and correlate runtime evidence inside the control plane.",
  },
  {
    value: "ingest.result_push",
    label: "Result push",
    mode: "Pushed ingest",
    detail: "Store pushed findings or inventory evidence from other approved producers.",
  },
  {
    value: "ingest.artifact_import",
    label: "Artifact import",
    mode: "Imported artifact",
    detail: "Use exported SBOMs, inventories, or third-party results as a customer-approved intake path.",
  },
  {
    value: "runtime.proxy",
    label: "MCP proxy runtime",
    mode: "Runtime",
    detail: "Track runtime evidence from agent-bom proxy deployment paths in customer-controlled environments.",
  },
  {
    value: "runtime.gateway",
    label: "MCP gateway runtime",
    mode: "Runtime",
    detail: "Treat the MCP gateway as a first-class runtime source with policy-audited upstream traffic.",
  },
];


export function kindOption(kind: SourceKind | string): KindOption | undefined {
  return SOURCE_KIND_OPTIONS.find((option) => option.value === kind);
}


export const DEFAULT_FORM_STATE: FormState = {
  display_name: "",
  kind: "scan.repo",
  target: "",
  description: "",
  owner: "",
  connector_name: "",
};


export interface FormState {
  display_name: string;
  kind: SourceKind;
  target: string;
  description: string;
  owner: string;
  connector_name: string;
}


export interface SourceTargetSpec {
  label: string;
  placeholder: string;
  requiredMessage: string;
  help: string;
}


export function sourceTargetSpec(kind: SourceKind): SourceTargetSpec | null {
  switch (kind) {
    case "scan.repo":
      return {
        label: "Repository URL",
        placeholder: "https://github.com/org/repository",
        requiredMessage: "Repository URL is required for a repo scan source.",
        help: "Agent-Bom shallow-clones this public HTTP(S) repository and statically scans the returned tree.",
      };
    case "scan.image":
      return {
        label: "Container image",
        placeholder: "ghcr.io/org/app:v1",
        requiredMessage: "Container image is required for an image scan source.",
        help: "Use an immutable tag or digest when repeatable snapshot comparison matters.",
      };
    case "scan.iac":
      return {
        label: "IaC repository URL",
        placeholder: "https://github.com/org/infrastructure",
        requiredMessage: "Repository URL is required for an IaC scan source.",
        help: "The queued job scans Terraform and Kubernetes files in this repository without executing repository code.",
      };
    case "scan.mcp_config":
      return {
        label: "Configuration repository URL",
        placeholder: "https://github.com/org/agent-configs",
        requiredMessage: "Repository URL is required for an MCP configuration source.",
        help: "Use a repository containing the MCP and agent configuration that the control plane should inspect.",
      };
    default:
      return null;
  }
}


export function scanRequestForSourceTarget(kind: SourceKind, target: string): Record<string, unknown> {
  if (kind === "scan.image") return { images: [target] };
  return { repo_url: target };
}


export const SCHEDULABLE_KINDS = new Set<SourceKind>([
  "scan.repo",
  "scan.image",
  "scan.iac",
  "scan.cloud",
  "scan.mcp_config",
  "connector.cloud_read_only",
  "connector.registry",
  "connector.warehouse",
]);


export const OPERATING_SURFACES = [
  {
    title: "Security graph and path analysis",
    href: "/security-graph",
    summary:
      "Persisted graph snapshots, attack-path focus, and blast-radius analysis across agents, servers, packages, tools, and credentials.",
    status: "Analyze",
    icon: Workflow,
  },
  {
    title: "Fleet management",
    href: "/fleet",
    summary: "Persisted fleet inventory and trust posture once the data lands in the control plane.",
    status: "Operate",
    icon: Activity,
  },
  {
    title: "Runtime proxy and alerts",
    href: "/runtime?tab=proxy",
    summary:
      "Live runtime enforcement, detector alerts, drift protection, and audit review for MCP and tool-call activity.",
    status: "Runtime",
    icon: Radio,
  },
  {
    title: "Gateway and policy enforcement",
    href: "/runtime?tab=gateway",
    summary: "Policy evaluation and enforcement for high-impact tool usage and approval workflows.",
    status: "Protect",
    icon: Shield,
  },
];


// ── Connector picker catalog (Connect segment) ────────────────────────────────

export type ConnectorCategory = "cloud" | "code" | "ai" | "data";


export type ConnectorAction =
  | { type: "cloud"; provider: string }
  | { type: "source"; sourceKind: SourceKind }
  | { type: "coding-agent" };


export interface CatalogConnector {
  id: string;
  category: ConnectorCategory;
  label: string;
  tagline: string;
  logo?: string;
  icon: React.ComponentType<{ className?: string }>;
  keywords?: string;
  action: ConnectorAction;
}


export const CONNECTOR_CATALOG: CatalogConnector[] = [
  ...PROVIDER_OPTIONS.map((option): CatalogConnector => ({
    id: option.value,
    category: "cloud",
    label: option.label,
    tagline: option.tagline,
    logo: option.value,
    icon: Cloud,
    keywords: `${option.permissions} cspm cis inventory`,
    action: { type: "cloud", provider: option.value },
  })),
  {
    id: "repo",
    category: "code",
    label: "Repositories",
    tagline: "Git repo & package (SCA) scan",
    logo: "github",
    icon: GitBranch,
    keywords: "git github gitlab sbom sca packages dependencies aspm",
    action: { type: "source", sourceKind: "scan.repo" },
  },
  {
    id: "image",
    category: "code",
    label: "Container images",
    tagline: "Image & OS package scan",
    icon: Container,
    keywords: "docker oci containers registry trivy os packages",
    action: { type: "source", sourceKind: "scan.image" },
  },
  {
    id: "iac",
    category: "code",
    label: "IaC & clusters",
    tagline: "Terraform & Kubernetes scan",
    icon: FileCode,
    keywords: "terraform k8s kubernetes helm iac misconfiguration",
    action: { type: "source", sourceKind: "scan.iac" },
  },
  {
    id: "saas-connector",
    category: "data",
    label: "SaaS connector",
    tagline: "Installed Jira, ServiceNow, or Slack connector",
    icon: Plug,
    keywords: "jira servicenow slack saas automation connector",
    action: { type: "source", sourceKind: "connector.cloud_read_only" },
  },
  {
    id: "mcp",
    category: "ai",
    label: "MCP configs",
    tagline: "Repository MCP configuration scan",
    icon: Plug,
    keywords: "model context protocol mcp servers tools aispm",
    action: { type: "source", sourceKind: "scan.mcp_config" },
  },
  {
    id: "coding-agent",
    category: "ai",
    label: "Coding agent",
    tagline: "Claude & Cursor via MCP + skills",
    logo: "claude",
    icon: Bot,
    keywords: "claude cursor mcp server skills cortex openclaw agent",
    action: { type: "coding-agent" },
  },
];


export const CONNECTOR_CATEGORIES: {
  id: ConnectorCategory | "all";
  label: string;
}[] = [
  { id: "all", label: "All" },
  { id: "cloud", label: "Cloud" },
  { id: "code", label: "Code" },
  { id: "ai", label: "AI" },
  { id: "data", label: "Data" },
];


export const CONNECTOR_CATEGORY_TONE: Record<ConnectorCategory, string> = {
  cloud: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-200",
  code: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200",
  ai: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200",
  data: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200",
};


export const CATEGORY_CHIP_TONE: Record<SourceCategory, string> = {
  cloud: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-200",
  code: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200",
  ai: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200",
  data: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200",
  runtime: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-200",
  ingest: "border-outline bg-surface-elevated text-ink-secondary",
};


export const SCHEDULE_OPTIONS = [
  ["Manual", ""],
  ["Hourly", "60"],
  ["Every 6 hours", "360"],
  ["Daily", "1440"],
] as const;


export function formatWhen(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}


export function formatWhenShort(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}


export function formatShortId(value: string, head = 10, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}


export function formatMode(value: string): string {
  return value.replaceAll("_", " ");
}


export function eventMode(connection: CloudConnectionRecord): {
  label: string;
  detail: string;
  tone: string;
} {
  if (connection.last_event_at) {
    return {
      label: "Event-driven",
      detail: `Last event ${formatWhen(connection.last_event_at)}`,
      tone: "border-cyan-500/30 dark:border-cyan-900/60 bg-cyan-500/10 dark:bg-cyan-950/30 text-cyan-700 dark:text-cyan-200",
    };
  }
  if (connection.scan_interval_minutes) {
    return {
      label: "Scheduled scan",
      detail: `Every ${connection.scan_interval_minutes} min`,
      tone: "border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/30 text-amber-700 dark:text-amber-200",
    };
  }
  return {
    label: "Manual",
    detail: "No scheduled or event run yet",
    tone: "border-outline bg-surface-elevated text-ink-secondary",
  };
}


// The stored inventory_scope column is the single authority for scan fan-out;
// the API promotes a legacy auth_params scope into it, so never read the blob
// here — the chip would otherwise claim a blast radius the scan does not use.
export function isOrganizationScope(connection: CloudConnectionRecord): boolean {
  return connection.inventory_scope === "organization";
}


export function isContinuousMode(connection: CloudConnectionRecord): boolean {
  return (connection.scan_mode ?? "full") === "continuous";
}


export function statusTone(status: string): string {
  switch (status) {
    case "active":
      return "border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300";
    case "error":
      return "border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/30 text-red-700 dark:text-red-300";
    default:
      return "border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300";
  }
}
