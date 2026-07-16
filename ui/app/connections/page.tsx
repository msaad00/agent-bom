"use client";

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Cloud,
  Plus,
  RefreshCcw,
  ShieldCheck,
  Trash2,
  X,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ArrowRight,
  ArrowLeft,
  ChevronRight,
  Boxes,
  Fingerprint,
  KeyRound,
  FileSearch,
  GitGraph,
  ListChecks,
  ClipboardList,
  Copy,
  Plug,
  Terminal,
  Search,
  GitBranch,
  Container,
  FileCode,
  Database,
  Bot,
  Package,
  Loader2,
  Activity,
  CalendarClock,
  FileCheck2,
  Radio,
  ServerCog,
  Shield,
  Workflow,
} from "lucide-react";

import {
  api,
  type CloudConnectionRecord,
  type CloudConnectionCreateRequest,
  type CloudConnectionTestResponse,
  type CloudConnectionScanResponse,
  type ConnectorHealthResponse,
  type DiscoveryProviderContract,
  type DiscoveryProvidersResponse,
  type ScanSchedule,
  type SourceCreateRequest,
  type SourceKind,
  type SourceRecord,
} from "@/lib/api";
import {
  buildUnifiedRows,
  categoryCounts,
  filterUnifiedRows,
  SOURCE_CATEGORY_OPTIONS,
  statusOptions,
  type SourceCategory,
  type UnifiedSourceRow,
} from "@/lib/connections-sources";
import { useAuthState } from "@/components/auth-provider";
import { ErrorBanner } from "@/components/empty-state";
import { PageEmptyState } from "@/components/states/page-state";
import { ServiceStateBanner, ServiceStateChip } from "@/components/service-state-chip";
import { Card, Section } from "@/components/card";
import { Collapsible } from "@/components/collapsible";
import { PageLaneHeader } from "@/components/page-lane";
import { Drawer } from "@/components/drawer";
import { CoverageCockpit } from "@/components/coverage-cockpit";
import { StatCard } from "@/components/stat-card";
import { StatStrip } from "@/components/stat-strip";
import { DemoConnectCard } from "@/components/demo-mode-cta";
import { useDemoMode } from "@/hooks/use-demo-mode";
import { useDeploymentContext } from "@/hooks/use-deployment-context";
import { deploymentModeLabel } from "@/lib/deployment-context";
import {
  buildGrantScript,
  cloudGrantMethodHint,
  cloudGrantMethodLabel,
  cloudProviderMeta,
  CLOUD_GRANT_METHODS,
  copyTextToClipboard,
  generateConnectionExternalId,
  type CloudGrantMethod,
} from "@/lib/cloud-connect-wizard";
import { serviceEntry } from "@/lib/service-registry";
import { vendorLogo } from "@/lib/vendor-logos";
import { FirstRunJourney } from "@/components/first-run-journey";
import {
  PermissionDeniedNotice,
  RoleBadge,
  RolePermissionsPanel,
} from "@/components/role-access";

// ── Hub tabs ────────────────────────────────────────────────────────────────
// One Connections hub with two URL-synced segments: Connect (add any source —
// cloud account, repo, image, IaC, MCP, warehouse, or a coding agent) and
// Sources (one dense, filterable table of everything registered — cloud
// connections + registered sources merged and deduped). Retires the separate
// `/sources` route (kept as a redirect).

type HubTab = "connect" | "sources";

function parseTab(value: string | null): HubTab {
  return value === "sources" ? "sources" : "connect";
}

// ── Provider catalog ──────────────────────────────────────────────────────────
// Every option maps its wizard fields onto the connection's role_ref (plaintext
// principal ref), external_id (the one write-only secret), and auth_params
// (non-secret provider params). `permissions` / `cli` mirror the real
// `agent-bom connect <provider>` onboarding (src/agent_bom/cli/_entry_points.py).

type ProviderReadiness = "live";

interface ProviderField {
  key: string;
  label: string;
  placeholder: string;
  mono?: boolean;
}

interface ProviderOption {
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

const PROVIDER_OPTIONS: ProviderOption[] = [
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
    tagline: "Read-only key-pair connection",
    permissions: "Read-only governance role (key-pair auth)",
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

function providerOption(value: string): ProviderOption | undefined {
  return PROVIDER_OPTIONS.find((option) => option.value === value);
}

function providerLabel(value: string): string {
  return providerOption(value)?.label ?? value.toUpperCase();
}

const SCANNABLE_PROVIDERS = new Set(PROVIDER_OPTIONS.map((option) => option.value));

// ── Source registration catalog ───────────────────────────────────────────────

type IngestMode =
  | "Direct scan"
  | "Read-only connector"
  | "Pushed ingest"
  | "Runtime"
  | "Imported artifact";

interface KindOption {
  value: SourceKind;
  label: string;
  mode: IngestMode;
  detail: string;
}

const SOURCE_KIND_OPTIONS: KindOption[] = [
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
    label: "Cloud API connector",
    mode: "Read-only connector",
    detail: "Use a named backend connector to read approved cloud APIs with customer-managed credentials.",
  },
  {
    value: "connector.registry",
    label: "Registry / package connector",
    mode: "Read-only connector",
    detail: "Attach registry-style connectors and run them as first-class sources.",
  },
  {
    value: "connector.warehouse",
    label: "Warehouse / lake connector",
    mode: "Read-only connector",
    detail: "Consume inventory or security-lake evidence from the customer’s existing data platform.",
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

function kindOption(kind: SourceKind | string): KindOption | undefined {
  return SOURCE_KIND_OPTIONS.find((option) => option.value === kind);
}

const DEFAULT_FORM_STATE: FormState = {
  display_name: "",
  kind: "scan.repo",
  description: "",
  owner: "",
  connector_name: "",
};

interface FormState {
  display_name: string;
  kind: SourceKind;
  description: string;
  owner: string;
  connector_name: string;
}

const SCHEDULABLE_KINDS = new Set<SourceKind>([
  "scan.repo",
  "scan.image",
  "scan.iac",
  "scan.cloud",
  "scan.mcp_config",
  "connector.cloud_read_only",
  "connector.registry",
  "connector.warehouse",
]);

const OPERATING_SURFACES = [
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

type ConnectorCategory = "cloud" | "code" | "ai" | "data";

type ConnectorAction =
  | { type: "cloud"; provider: string }
  | { type: "source"; sourceKind: SourceKind }
  | { type: "coding-agent" };

interface CatalogConnector {
  id: string;
  category: ConnectorCategory;
  label: string;
  tagline: string;
  logo?: string;
  icon: React.ComponentType<{ className?: string }>;
  keywords?: string;
  action: ConnectorAction;
}

const CONNECTOR_CATALOG: CatalogConnector[] = [
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
    id: "registry",
    category: "code",
    label: "Package registry",
    tagline: "Read-only registry connector",
    icon: Package,
    keywords: "npm pypi maven artifactory ghcr registry connector",
    action: { type: "source", sourceKind: "connector.registry" },
  },
  {
    id: "mcp",
    category: "ai",
    label: "MCP configs",
    tagline: "Local MCP configuration scan",
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
  {
    id: "warehouse",
    category: "data",
    label: "Warehouse & lake",
    tagline: "Snowflake, BigQuery read-only",
    icon: Database,
    keywords: "snowflake bigquery redshift databricks dspm data lake connector",
    action: { type: "source", sourceKind: "connector.warehouse" },
  },
];

const CONNECTOR_CATEGORIES: {
  id: ConnectorCategory | "all";
  label: string;
}[] = [
  { id: "all", label: "All" },
  { id: "cloud", label: "Cloud" },
  { id: "code", label: "Code" },
  { id: "ai", label: "AI" },
  { id: "data", label: "Data" },
];

const CONNECTOR_CATEGORY_TONE: Record<ConnectorCategory, string> = {
  cloud: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-200",
  code: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200",
  ai: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200",
  data: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200",
};

const CATEGORY_CHIP_TONE: Record<SourceCategory, string> = {
  cloud: "border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-200",
  code: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200",
  ai: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-200",
  data: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200",
  runtime: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-200",
  ingest: "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[color:var(--text-secondary)]",
};

const SCHEDULE_OPTIONS = [
  ["Manual", ""],
  ["Hourly", "60"],
  ["Every 6 hours", "360"],
  ["Daily", "1440"],
] as const;

function formatWhen(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatWhenShort(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function formatShortId(value: string, head = 10, tail = 6): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function formatMode(value: string): string {
  return value.replaceAll("_", " ");
}

function eventMode(connection: CloudConnectionRecord): {
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
    tone: "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[var(--text-secondary)]",
  };
}

function statusTone(status: string): string {
  switch (status) {
    case "active":
      return "border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300";
    case "error":
      return "border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/30 text-red-700 dark:text-red-300";
    default:
      return "border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300";
  }
}

function StatusPill({ status }: { status: string }) {
  const Icon =
    status === "active"
      ? CheckCircle2
      : status === "error"
        ? AlertTriangle
        : Clock;
  const label =
    status === "active" ? "Active" : status === "error" ? "Error" : "Pending";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${statusTone(status)}`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </span>
  );
}

const SOURCE_STATUS_TONE: Record<string, string> = {
  healthy: "var(--status-success)",
  done: "var(--status-success)",
  active: "var(--status-success)",
  configured: "var(--accent)",
  degraded: "var(--status-warn)",
  paused: "var(--status-warn)",
  pending: "var(--status-warn)",
  disabled: "var(--text-tertiary)",
  error: "var(--status-danger)",
  failed: "var(--status-danger)",
};

function sourceStatusColor(status: string): string {
  return SOURCE_STATUS_TONE[status.toLowerCase()] ?? "var(--accent)";
}

function SourceStatusPill({ status }: { status: string }) {
  const tone = sourceStatusColor(status);
  return (
    <span
      className="inline-flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.1em]"
      style={{ color: tone }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: tone }} aria-hidden="true" />
      {status}
    </span>
  );
}

const MODE_DOT: Record<IngestMode, string> = {
  "Direct scan": "var(--status-success)",
  "Read-only connector": "var(--severity-low)",
  "Pushed ingest": "var(--status-warn)",
  Runtime: "var(--severity-high)",
  "Imported artifact": "var(--text-tertiary)",
};

function ModeChip({ mode }: { mode: IngestMode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-0.5 text-[11px] font-medium text-[color:var(--text-secondary)]">
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: MODE_DOT[mode] }} aria-hidden="true" />
      {mode}
    </span>
  );
}

function formatPassRate(rate: number | null): string {
  if (rate == null) return "—";
  const pct = rate <= 1 ? rate * 100 : rate;
  return `${pct.toFixed(0)}%`;
}

function evidenceLinks(scanId: string) {
  const encoded = encodeURIComponent(scanId);
  return [
    { label: "Scan result", href: `/scan?id=${encoded}`, icon: FileSearch },
    { label: "Jobs", href: `/jobs?q=${encoded}`, icon: ClipboardList },
    { label: "Findings", href: `/findings?scan=${encoded}`, icon: ListChecks },
    { label: "Graph", href: `/graph?scan_id=${encoded}`, icon: GitGraph },
    { label: "Compliance", href: `/compliance?q=${encoded}`, icon: ShieldCheck },
  ];
}

function sourceEvidenceHref(
  source: SourceRecord,
  target: "jobs" | "findings" | "graph" | "compliance",
): string {
  const jobId = source.last_job_id ?? "";
  if (target === "jobs" || !jobId) return `/jobs?q=${encodeURIComponent(source.source_id)}`;
  const route = target === "graph" ? "security-graph" : target;
  return `/${route}?scan=${encodeURIComponent(jobId)}`;
}

function summarizeProviders(contracts: DiscoveryProvidersResponse | null) {
  const providers = contracts?.providers ?? [];
  return {
    total: providers.length,
    readOnly: providers.filter((provider) => provider.trust_contract.read_only).length,
    scopeZero: providers.filter((provider) => provider.trust_contract.supports_scope_zero).length,
    permissionCount: providers.reduce(
      (total, provider) => total + provider.capabilities.permissions_used.length,
      0,
    ),
  };
}

function ProviderLogo({
  provider,
  className = "h-7 w-7",
}: {
  provider: string;
  className?: string;
}) {
  const src = vendorLogo(provider);
  if (!src) {
    return <Cloud className={`${className} text-emerald-400`} aria-hidden="true" />;
  }
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src={src} alt={`${providerLabel(provider)} logo`} className={`${className} object-contain`} />
  );
}

// ── Page shell (Suspense boundary for useSearchParams) ────────────────────────

export default function ConnectionsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
        </div>
      }
    >
      <ConnectionsHub />
    </Suspense>
  );
}

function ConnectionsHub() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const tab = parseTab(searchParams.get("tab"));

  const { hasCapability, session } = useAuthState();
  const { counts } = useDeploymentContext();
  const { isDemoMode } = useDemoMode();
  const canManage = !session?.auth_required || hasCapability("scan.run");
  const canManageSources = !session?.auth_required || hasCapability("sources.manage");
  const canRunScans = !session?.auth_required || hasCapability("scan.run");
  const canManageFleet = hasCapability("fleet.manage");
  const cloudService = serviceEntry(counts?.services, "cloud_accounts");
  const dataSourcesService = serviceEntry(counts?.services, "data_sources");

  // Cloud connections.
  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardProvider, setWizardProvider] = useState<string | undefined>(undefined);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, CloudConnectionScanResponse>>({});
  const [scanErrors, setScanErrors] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<Record<string, CloudConnectionTestResponse>>({});
  const [scheduleErrors, setScheduleErrors] = useState<Record<string, string>>({});

  // Registered sources + control-plane source state.
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [connectorHealth, setConnectorHealth] = useState<ConnectorHealthResponse[]>([]);
  const [providerContracts, setProviderContracts] = useState<DiscoveryProvidersResponse | null>(null);
  const [formMessage, setFormMessage] = useState<string | null>(null);
  const [busySourceId, setBusySourceId] = useState<string | null>(null);
  const [busyScheduleId, setBusyScheduleId] = useState<string | null>(null);
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [formState, setFormState] = useState<FormState>(DEFAULT_FORM_STATE);
  const [submitting, setSubmitting] = useState(false);
  const [submittingSchedule, setSubmittingSchedule] = useState(false);
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleCron, setScheduleCron] = useState("0 * * * *");
  const [createNonce, setCreateNonce] = useState(0);
  const [syncingFleet, setSyncingFleet] = useState(false);
  const [fleetSyncSummary, setFleetSyncSummary] = useState<string | null>(null);

  // Connect gallery + coding-agent.
  const [galleryCategory, setGalleryCategory] = useState<ConnectorCategory | "all">("all");
  const [gallerySearch, setGallerySearch] = useState("");
  const [codingAgentOpen, setCodingAgentOpen] = useState(false);

  // Unified table filters.
  const [filterCategory, setFilterCategory] = useState<SourceCategory | "all">("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterQuery, setFilterQuery] = useState("");

  const setTab = useCallback(
    (next: HubTab) => {
      router.replace(next === "connect" ? "/connections" : "/connections?tab=sources");
    },
    [router],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listCloudConnections();
      setConnections(result.connections);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load cloud connections.");
      setConnections([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshSources = useCallback(async () => {
    setSourcesLoading(true);
    try {
      const [connectorsResult, schedulesResult, sourcesResult, providerContractsResult] =
        await Promise.allSettled([
          api.listConnectors(),
          api.listSchedules(),
          api.listSources(),
          api.listDiscoveryProviders(),
        ]);

      if (sourcesResult.status === "fulfilled") {
        setSources(sourcesResult.value.sources ?? []);
      } else {
        setSources([]);
      }

      if (providerContractsResult.status === "fulfilled") {
        setProviderContracts(providerContractsResult.value);
      } else {
        setProviderContracts(null);
      }

      if (schedulesResult.status === "fulfilled") {
        const sorted = [...schedulesResult.value].sort((left, right) => {
          const leftTime = left.next_run ? Date.parse(left.next_run) : Number.POSITIVE_INFINITY;
          const rightTime = right.next_run ? Date.parse(right.next_run) : Number.POSITIVE_INFINITY;
          return leftTime - rightTime;
        });
        setSchedules(sorted);
      } else {
        setSchedules([]);
      }

      if (connectorsResult.status === "fulfilled") {
        const healthResults = await Promise.allSettled(
          connectorsResult.value.connectors.map((name) => api.getConnectorHealth(name)),
        );
        setConnectorHealth(
          healthResults.flatMap((result) => (result.status === "fulfilled" ? [result.value] : [])),
        );
      } else {
        setConnectorHealth([]);
      }
    } finally {
      setSourcesLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    void refreshSources();
  }, [refresh, refreshSources]);

  const refreshAll = useCallback(() => {
    void refresh();
    void refreshSources();
  }, [refresh, refreshSources]);

  const openWizard = useCallback((provider?: string) => {
    setWizardProvider(provider);
    setWizardOpen(true);
  }, []);

  const handleCreated = useCallback(
    (created: CloudConnectionRecord) => {
      setWizardOpen(false);
      setMessage(`Connected ${created.display_name}.`);
      void refresh();
    },
    [refresh],
  );

  const handleRegisterSource = useCallback(
    (kind: SourceKind) => {
      setFormState((current) => ({ ...current, kind }));
      setCreateNonce((n) => n + 1);
      setTab("sources");
    },
    [setTab],
  );

  async function handleScan(connection: CloudConnectionRecord) {
    setBusyId(connection.id);
    setMessage(null);
    setScanErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const result = await api.scanCloudConnection(connection.id);
      setScanResults((prev) => ({ ...prev, [connection.id]: result }));
      await refresh();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Scan failed.";
      setScanErrors((prev) => ({ ...prev, [connection.id]: detail }));
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleTest(connection: CloudConnectionRecord) {
    setBusyId(connection.id);
    setMessage(null);
    setScanErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const result = await api.testCloudConnection(connection.id);
      setTestResults((prev) => ({ ...prev, [connection.id]: result }));
      setMessage(`${connection.display_name} read-only credential verified.`);
      await refresh();
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Connection test failed.";
      setScanErrors((prev) => ({ ...prev, [connection.id]: detail }));
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(connection: CloudConnectionRecord) {
    setBusyId(connection.id);
    setMessage(null);
    try {
      await api.deleteCloudConnection(connection.id);
      setScanResults((prev) => {
        const next = { ...prev };
        delete next[connection.id];
        return next;
      });
      setMessage(`Removed ${connection.display_name}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete connection.");
    } finally {
      setBusyId(null);
    }
  }

  async function handleScheduleChange(connection: CloudConnectionRecord, value: string) {
    const scanIntervalMinutes = value === "" ? null : Number(value);
    setScheduleErrors((prev) => {
      const next = { ...prev };
      delete next[connection.id];
      return next;
    });
    try {
      const updated = await api.updateCloudConnection(connection.id, {
        scan_interval_minutes: scanIntervalMinutes,
      });
      setConnections((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
      setMessage(`${updated.display_name} scan schedule updated.`);
    } catch (err) {
      const detail = err instanceof Error ? err.message : "Failed to update schedule.";
      setScheduleErrors((prev) => ({ ...prev, [connection.id]: detail }));
    }
  }

  async function handleFleetSync() {
    setSyncingFleet(true);
    setFleetSyncSummary(null);
    try {
      const result = await api.syncFleet();
      setFleetSyncSummary(`${result.synced} synced · ${result.new} new · ${result.updated} updated`);
      await refreshSources();
    } catch (err) {
      setFleetSyncSummary(err instanceof Error ? err.message : "Fleet sync failed");
    } finally {
      setSyncingFleet(false);
    }
  }

  function updateForm<K extends keyof FormState>(field: K, value: FormState[K]) {
    setFormState((current) => ({ ...current, [field]: value }));
  }

  async function handleCreateSource(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormMessage(null);
    const selected = kindOption(formState.kind) ?? SOURCE_KIND_OPTIONS[0]!;

    const payload: SourceCreateRequest = {
      display_name: formState.display_name.trim(),
      kind: formState.kind,
      description: formState.description.trim(),
      owner: formState.owner.trim(),
      enabled: true,
      credential_mode: selected.mode === "Read-only connector" ? "reference" : "none",
    };

    if (!payload.display_name) {
      setFormMessage("Display name is required.");
      return;
    }
    if (selected.mode === "Read-only connector") {
      if (!formState.connector_name.trim()) {
        setFormMessage("Connector-backed sources require a connector name.");
        return;
      }
      payload.connector_name = formState.connector_name.trim();
    }

    setSubmitting(true);
    try {
      await api.createSource(payload);
      setFormMessage(`Created source ${payload.display_name}.`);
      setFormState({ ...DEFAULT_FORM_STATE, kind: payload.kind });
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Failed to create source.");
    } finally {
      setSubmitting(false);
    }
  }

  async function runSourceAction(sourceId: string, action: "test" | "run" | "delete") {
    setBusySourceId(sourceId);
    setFormMessage(null);
    try {
      if (action === "test") {
        const result = await api.testSource(sourceId);
        setFormMessage(result.message);
      } else if (action === "run") {
        const result = await api.runSource(sourceId);
        setFormMessage(`Queued job ${result.job_id}.`);
      } else {
        await api.deleteSource(sourceId);
        setFormMessage("Source deleted.");
        setSelectedSourceId(null);
      }
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Source action failed.");
    } finally {
      setBusySourceId(null);
    }
  }

  async function handleCreateSchedule(event: React.FormEvent<HTMLFormElement>, source: SourceRecord) {
    event.preventDefault();
    setFormMessage(null);
    if (!scheduleCron.trim()) {
      setFormMessage("Cron expression is required.");
      return;
    }
    const name = scheduleName.trim() || `${source.display_name} recurring run`;
    setSubmittingSchedule(true);
    try {
      await api.createSchedule({
        name,
        cron_expression: scheduleCron.trim(),
        enabled: true,
        scan_config: { source_id: source.source_id },
      });
      setFormMessage(`Created schedule ${name}.`);
      setScheduleName("");
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Failed to create schedule.");
    } finally {
      setSubmittingSchedule(false);
    }
  }

  async function runScheduleAction(scheduleId: string, action: "toggle" | "delete") {
    setBusyScheduleId(scheduleId);
    setFormMessage(null);
    try {
      if (action === "toggle") {
        const updated = await api.toggleSchedule(scheduleId);
        setFormMessage(`${updated.name} ${updated.enabled ? "enabled" : "paused"}.`);
      } else {
        await api.deleteSchedule(scheduleId);
        setFormMessage("Schedule deleted.");
      }
      await refreshSources();
    } catch (err) {
      setFormMessage(err instanceof Error ? err.message : "Schedule action failed.");
    } finally {
      setBusyScheduleId(null);
    }
  }

  // Derived data.
  const lastAccountScan = useMemo(() => {
    const stamps = connections
      .map((c) => c.last_scan_at)
      .filter((v): v is string => Boolean(v))
      .sort((a, b) => b.localeCompare(a));
    return stamps[0] ?? null;
  }, [connections]);
  const hasConnections = connections.length > 0;

  const connectedByProvider = useMemo(() => {
    const map: Record<string, number> = {};
    for (const connection of connections) {
      map[connection.provider] = (map[connection.provider] ?? 0) + 1;
    }
    return map;
  }, [connections]);

  const sourceCountByKind = useMemo(() => {
    const map: Record<string, number> = {};
    for (const source of sources) {
      map[source.kind] = (map[source.kind] ?? 0) + 1;
    }
    return map;
  }, [sources]);

  const scheduleCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const schedule of schedules) {
      const linked =
        typeof schedule.scan_config?.source_id === "string"
          ? String(schedule.scan_config.source_id)
          : "";
      if (!linked) continue;
      map.set(linked, (map.get(linked) ?? 0) + 1);
    }
    return map;
  }, [schedules]);

  const schedulesBySource = useMemo(() => {
    const map = new Map<string, ScanSchedule[]>();
    for (const schedule of schedules) {
      const linked =
        typeof schedule.scan_config?.source_id === "string"
          ? String(schedule.scan_config.source_id)
          : "";
      if (!linked) continue;
      const list = map.get(linked) ?? [];
      list.push(schedule);
      map.set(linked, list);
    }
    return map;
  }, [schedules]);

  const unifiedRows = useMemo(
    () => buildUnifiedRows(connections, sources, scheduleCounts),
    [connections, sources, scheduleCounts],
  );
  const rowCategoryCounts = useMemo(() => categoryCounts(unifiedRows), [unifiedRows]);
  const rowStatusOptions = useMemo(() => statusOptions(unifiedRows), [unifiedRows]);
  const filteredRows = useMemo(
    () =>
      filterUnifiedRows(unifiedRows, {
        category: filterCategory,
        status: filterStatus,
        query: filterQuery,
      }),
    [unifiedRows, filterCategory, filterStatus, filterQuery],
  );

  const connectionById = useMemo(() => {
    const map = new Map<string, CloudConnectionRecord>();
    for (const connection of connections) map.set(connection.id, connection);
    return map;
  }, [connections]);
  const sourceById = useMemo(() => {
    const map = new Map<string, SourceRecord>();
    for (const source of sources) map.set(source.source_id, source);
    return map;
  }, [sources]);

  const connectorConnectedCount = useCallback(
    (connector: CatalogConnector): number => {
      if (connector.action.type === "cloud") {
        return connectedByProvider[connector.action.provider] ?? 0;
      }
      if (connector.action.type === "source") {
        return sourceCountByKind[connector.action.sourceKind] ?? 0;
      }
      return 0;
    },
    [connectedByProvider, sourceCountByKind],
  );

  const connectorNames = useMemo(
    () => connectorHealth.map((connector) => connector.connector).sort((l, r) => l.localeCompare(r)),
    [connectorHealth],
  );
  const healthyConnectors = useMemo(
    () => connectorHealth.filter((connector) => connector.state === "healthy").length,
    [connectorHealth],
  );
  const providerSummary = useMemo(() => summarizeProviders(providerContracts), [providerContracts]);

  const selectedSource = selectedSourceId ? sourceById.get(selectedSourceId) ?? null : null;

  const openRow = useCallback((row: UnifiedSourceRow) => {
    if (row.origin === "cloud" && row.connectionId) {
      setDetailId(row.connectionId);
    } else if (row.origin === "source" && row.sourceId) {
      setSelectedSourceId(row.sourceId);
    }
  }, []);

  const gallery = (
    <ConnectorGallery
      activeCategory={galleryCategory}
      onCategoryChange={setGalleryCategory}
      search={gallerySearch}
      onSearchChange={setGallerySearch}
      connectedCountFor={connectorConnectedCount}
      canManage={canManage}
      onConnectCloud={openWizard}
      onRegisterSource={handleRegisterSource}
      onConnectCodingAgent={() => setCodingAgentOpen(true)}
    />
  );

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="cloud-data"
        title="Connections"
        subtitle="One place to connect cloud, code, AI, and data — then see every registered source in one dense table."
        scopeChip={
          <span className="inline-flex items-center rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-[11px] font-medium text-purple-700 dark:text-purple-200">
            {deploymentModeLabel(counts?.deployment_mode)} · brokered read-only
          </span>
        }
        actions={
          <>
            <button
              onClick={refreshAll}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <RefreshCcw className="h-4 w-4" />
              Refresh
            </button>
            <button
              onClick={() => openWizard()}
              disabled={!canManage}
              className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
              Add cloud account
            </button>
          </>
        }
        banner={
          <div className="grid gap-3 sm:grid-cols-3">
            <StatCard label="Cloud accounts" value={loading ? "…" : connections.length} />
            <StatCard label="Registered sources" value={sourcesLoading ? "…" : sources.length} accent="info" />
            <StatCard label="Last scan" value={loading ? "…" : formatWhenShort(lastAccountScan)} />
          </div>
        }
      />

      <HubTabs tab={tab} onChange={setTab} connectCount={CONNECTOR_CATALOG.length} sourceCount={unifiedRows.length} />

      {message ? <p className="text-sm text-emerald-400">{message}</p> : null}
      {!canManage ? (
        <PermissionDeniedNotice
          session={session}
          needed="analyst"
          action="connect a cloud account, run a scan, or delete a connection"
        />
      ) : null}

      {tab === "connect" ? (
        <ConnectSegment
          session={session}
          counts={counts}
          cloudService={cloudService}
          connections={connections}
          connectionsCount={connections.length}
          scanCount={counts?.scan_count ?? 0}
          findingsCount={counts?.total ?? 0}
          canManage={canManage}
          hasConnections={hasConnections}
          gallery={gallery}
          onConnect={() => openWizard("aws")}
        />
      ) : (
        <SourcesSegment
          rows={filteredRows}
          totalRows={unifiedRows.length}
          categoryCountsMap={rowCategoryCounts}
          statusChoices={rowStatusOptions}
          filterCategory={filterCategory}
          onFilterCategory={setFilterCategory}
          filterStatus={filterStatus}
          onFilterStatus={setFilterStatus}
          filterQuery={filterQuery}
          onFilterQuery={setFilterQuery}
          loading={loading || sourcesLoading}
          error={error}
          onRetry={refreshAll}
          onRowOpen={openRow}
          connectionById={connectionById}
          busyId={busyId}
          canManage={canManage}
          onCloudTest={(c) => void handleTest(c)}
          onCloudScan={(c) => void handleScan(c)}
          onCloudDelete={(c) => void handleDelete(c)}
          onCloudScheduleChange={(c, v) => void handleScheduleChange(c, v)}
          isDemoMode={isDemoMode}
          dataSourcesService={dataSourcesService}
          servicesRegistry={counts?.services}
          formMessage={formMessage}
          fleetSyncSummary={fleetSyncSummary}
          syncingFleet={syncingFleet}
          canManageFleet={canManageFleet}
          onFleetSync={() => void handleFleetSync()}
          connectorHealth={connectorHealth}
          connectorNames={connectorNames}
          healthyConnectors={healthyConnectors}
          providerContracts={providerContracts}
          providerSummary={providerSummary}
          schedulesCount={schedules.length}
          nextSchedule={schedules[0]?.next_run ?? null}
          canManageSources={canManageSources}
          formState={formState}
          onUpdateForm={updateForm}
          submitting={submitting}
          onCreateSource={handleCreateSource}
          createDefaultOpen={createNonce > 0 || sources.length === 0}
          createKey={`create-${createNonce}`}
          onGoConnect={() => setTab("connect")}
        />
      )}

      <ConnectionDetailDrawer
        connection={detailId ? connectionById.get(detailId) ?? null : null}
        result={detailId ? scanResults[detailId] : undefined}
        testResult={detailId ? testResults[detailId] : undefined}
        scanError={detailId ? scanErrors[detailId] : undefined}
        scheduleError={detailId ? scheduleErrors[detailId] : undefined}
        isBusy={busyId === detailId}
        canManage={canManage}
        scannable={detailId ? SCANNABLE_PROVIDERS.has(connectionById.get(detailId)?.provider ?? "") : false}
        onClose={() => setDetailId(null)}
        onTest={(connection) => void handleTest(connection)}
        onScan={(connection) => void handleScan(connection)}
        onDelete={(connection) => {
          setDetailId(null);
          void handleDelete(connection);
        }}
      />

      <SourceDrawer
        source={selectedSource}
        open={selectedSource != null}
        onClose={() => setSelectedSourceId(null)}
        schedules={selectedSource ? schedulesBySource.get(selectedSource.source_id) ?? [] : []}
        busySourceId={busySourceId}
        busyScheduleId={busyScheduleId}
        canManageSources={canManageSources}
        canRunScans={canRunScans}
        onSourceAction={runSourceAction}
        onScheduleAction={runScheduleAction}
        onCreateSchedule={handleCreateSchedule}
        submittingSchedule={submittingSchedule}
        scheduleName={scheduleName}
        scheduleCron={scheduleCron}
        onScheduleNameChange={setScheduleName}
        onScheduleCronChange={setScheduleCron}
      />

      {wizardOpen ? (
        <AddConnectionWizard
          initialProvider={wizardProvider}
          onClose={() => setWizardOpen(false)}
          onCreated={handleCreated}
        />
      ) : null}

      <CodingAgentDrawer open={codingAgentOpen} onClose={() => setCodingAgentOpen(false)} />
    </div>
  );
}

// ── Segmented control ─────────────────────────────────────────────────────────

function HubTabs({
  tab,
  onChange,
  connectCount,
  sourceCount,
}: {
  tab: HubTab;
  onChange: (tab: HubTab) => void;
  connectCount: number;
  sourceCount: number;
}) {
  const tabs: { key: HubTab; label: string; count: number; icon: typeof Plug }[] = [
    { key: "connect", label: "Connect", count: connectCount, icon: Plug },
    { key: "sources", label: "Sources", count: sourceCount, icon: Boxes },
  ];
  return (
    <div
      className="inline-flex items-center gap-1 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-1"
      role="tablist"
      aria-label="Connections segment"
    >
      {tabs.map((item) => {
        const Icon = item.icon;
        const selected = item.key === tab;
        return (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={selected}
            onClick={() => onChange(item.key)}
            className={`inline-flex items-center gap-2 rounded-lg px-4 py-1.5 text-sm font-medium transition-colors ${
              selected
                ? "bg-[color:var(--surface)] text-[color:var(--foreground)] shadow-sm"
                : "text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
            }`}
          >
            <Icon className="h-4 w-4" />
            {item.label}
            <span className="rounded-full border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 text-[10px] font-mono text-[color:var(--text-tertiary)]">
              {item.count}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// ── Connect segment ───────────────────────────────────────────────────────────

function ConnectSegment({
  session,
  counts,
  cloudService,
  connections,
  connectionsCount,
  scanCount,
  findingsCount,
  canManage,
  hasConnections,
  gallery,
  onConnect,
}: {
  session: ReturnType<typeof useAuthState>["session"];
  counts: ReturnType<typeof useDeploymentContext>["counts"];
  cloudService: ReturnType<typeof serviceEntry>;
  connections: CloudConnectionRecord[];
  connectionsCount: number;
  scanCount: number;
  findingsCount: number;
  canManage: boolean;
  hasConnections: boolean;
  gallery: React.ReactNode;
  onConnect: () => void;
}) {
  return (
    <div className="space-y-6">
      <FirstRunJourney
        connectionsCount={connectionsCount}
        scanCount={scanCount}
        findingsCount={findingsCount}
        canManage={canManage}
        session={session}
        onConnect={onConnect}
      />

      <div className="flex flex-wrap items-center gap-2">
        <RoleBadge session={session} />
        <ServiceStateChip
          serviceId="cloud_accounts"
          entry={cloudService}
          registry={counts?.services}
          showUnlock={false}
        />
      </div>

      <ServiceStateBanner serviceId="cloud_accounts" entry={cloudService} registry={counts?.services} />

      <CoverageCockpit
        counts={counts}
        scanCount={counts?.scan_count ?? null}
        latestScanLabel={null}
        connections={connections}
      />

      <Section
        label="Connect a source"
        description="Cloud accounts open a read-only wizard; code, AI, and data sources register in the control plane and appear under Sources."
      >
        {gallery}
      </Section>

      {!hasConnections ? (
        <p className="text-sm text-[color:var(--text-secondary)]">
          Once a source is connected, switch to <span className="font-medium text-[color:var(--foreground)]">Sources</span> to
          see it in the unified table with scan handoff, schedules, and evidence links.
        </p>
      ) : null}

      <Collapsible
        title="Roles & permissions"
        subtitle="Viewer reads · Contributor connects and scans · Admin manages keys, policy, and fleet."
        defaultOpen={false}
        data-testid="roles-permissions"
      >
        <RolePermissionsPanel session={session} bare />
      </Collapsible>
    </div>
  );
}

// ── Sources segment (unified table + management) ──────────────────────────────

interface SourcesSegmentProps {
  rows: UnifiedSourceRow[];
  totalRows: number;
  categoryCountsMap: Record<SourceCategory | "all", number>;
  statusChoices: string[];
  filterCategory: SourceCategory | "all";
  onFilterCategory: (value: SourceCategory | "all") => void;
  filterStatus: string;
  onFilterStatus: (value: string) => void;
  filterQuery: string;
  onFilterQuery: (value: string) => void;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  onRowOpen: (row: UnifiedSourceRow) => void;
  connectionById: Map<string, CloudConnectionRecord>;
  busyId: string | null;
  canManage: boolean;
  onCloudTest: (connection: CloudConnectionRecord) => void;
  onCloudScan: (connection: CloudConnectionRecord) => void;
  onCloudDelete: (connection: CloudConnectionRecord) => void;
  onCloudScheduleChange: (connection: CloudConnectionRecord, value: string) => void;
  isDemoMode: boolean;
  dataSourcesService: ReturnType<typeof serviceEntry>;
  servicesRegistry: Parameters<typeof serviceEntry>[0];
  formMessage: string | null;
  fleetSyncSummary: string | null;
  syncingFleet: boolean;
  canManageFleet: boolean;
  onFleetSync: () => void;
  connectorHealth: ConnectorHealthResponse[];
  connectorNames: string[];
  healthyConnectors: number;
  providerContracts: DiscoveryProvidersResponse | null;
  providerSummary: ReturnType<typeof summarizeProviders>;
  schedulesCount: number;
  nextSchedule: string | null;
  canManageSources: boolean;
  formState: FormState;
  onUpdateForm: <K extends keyof FormState>(field: K, value: FormState[K]) => void;
  submitting: boolean;
  onCreateSource: (event: React.FormEvent<HTMLFormElement>) => void;
  createDefaultOpen: boolean;
  createKey: string;
  onGoConnect: () => void;
}

function SourcesSegment(props: SourcesSegmentProps) {
  const {
    rows,
    totalRows,
    categoryCountsMap,
    statusChoices,
    filterCategory,
    onFilterCategory,
    filterStatus,
    onFilterStatus,
    filterQuery,
    onFilterQuery,
    loading,
    error,
    onRetry,
    onRowOpen,
    connectionById,
    busyId,
    canManage,
    onCloudTest,
    onCloudScan,
    onCloudDelete,
    onCloudScheduleChange,
    isDemoMode,
    dataSourcesService,
    servicesRegistry,
    formMessage,
    fleetSyncSummary,
    syncingFleet,
    canManageFleet,
    onFleetSync,
    connectorHealth,
    connectorNames,
    healthyConnectors,
    providerContracts,
    providerSummary,
    schedulesCount,
    nextSchedule,
    canManageSources,
    formState,
    onUpdateForm,
    submitting,
    onCreateSource,
    createDefaultOpen,
    createKey,
    onGoConnect,
  } = props;

  const selectedKind = kindOption(formState.kind) ?? SOURCE_KIND_OPTIONS[0]!;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <ServiceStateChip
          serviceId="data_sources"
          entry={dataSourcesService}
          registry={servicesRegistry}
          showUnlock={false}
        />
        {!isDemoMode ? (
          <button
            onClick={onFleetSync}
            disabled={syncingFleet || !canManageFleet}
            className="inline-flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Activity className="h-3.5 w-3.5" />
            {syncingFleet ? "Syncing…" : "Fleet sync"}
          </button>
        ) : null}
      </div>

      <ServiceStateBanner serviceId="data_sources" entry={dataSourcesService} registry={servicesRegistry} />
      {isDemoMode ? <DemoConnectCard /> : null}

      <StatStrip
        data-testid="sources-kpis"
        items={[
          { label: "Registered", value: loading ? "…" : totalRows },
          {
            label: "Connector health",
            value: loading ? "…" : `${healthyConnectors}/${connectorHealth.length || 0}`,
            accent:
              connectorHealth.length > 0 && healthyConnectors === connectorHealth.length
                ? "success"
                : "neutral",
          },
          {
            label: "Schedules",
            value: loading ? "…" : schedulesCount,
            hint: nextSchedule ? `Next ${formatWhen(nextSchedule)}` : "None yet",
          },
          {
            label: "Providers",
            value: loading ? "…" : providerSummary.total,
            hint: `${providerSummary.readOnly} read-only`,
          },
        ]}
      />

      {(fleetSyncSummary || formMessage) && (
        <div className="space-y-1 text-sm">
          {fleetSyncSummary ? <p className="text-[color:var(--status-success)]">{fleetSyncSummary}</p> : null}
          {formMessage ? <p className="text-[color:var(--accent)]">{formMessage}</p> : null}
        </div>
      )}

      <SourceFilterToolbar
        categoryCountsMap={categoryCountsMap}
        statusChoices={statusChoices}
        filterCategory={filterCategory}
        onFilterCategory={onFilterCategory}
        filterStatus={filterStatus}
        onFilterStatus={onFilterStatus}
        filterQuery={filterQuery}
        onFilterQuery={onFilterQuery}
      />

      {error ? (
        <ErrorBanner message={error} onRetry={onRetry} />
      ) : loading && totalRows === 0 ? (
        <div className="space-y-2" aria-busy="true">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="h-14 animate-pulse rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]"
            />
          ))}
        </div>
      ) : totalRows === 0 ? (
        <PageEmptyState
          icon={ServerCog}
          title="No sources connected yet"
          detail="Connect a cloud account, repo, image, IaC, MCP config, or warehouse to see it here with scan handoff, schedules, and evidence."
          suggestions={[
            "Cloud accounts add read-only AWS, Azure, GCP, or Snowflake inventory + CIS.",
            "Code, AI, and data sources register in the control plane and run as jobs.",
          ]}
          actions={[{ label: "Connect a source", onClick: onGoConnect }]}
        />
      ) : rows.length === 0 ? (
        <p className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-10 text-center text-sm text-[color:var(--text-secondary)]">
          No sources match the current filters.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[color:var(--border-subtle)]" data-testid="unified-sources-table">
          <table className="w-full min-w-[1000px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[11px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Kind</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Last scan</th>
                <th className="px-4 py-3 font-medium">Schedule</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <UnifiedRow
                  key={row.id}
                  row={row}
                  connection={row.connectionId ? connectionById.get(row.connectionId) ?? null : null}
                  busyId={busyId}
                  canManage={canManage}
                  onOpen={() => onRowOpen(row)}
                  onCloudTest={onCloudTest}
                  onCloudScan={onCloudScan}
                  onCloudDelete={onCloudDelete}
                  onCloudScheduleChange={onCloudScheduleChange}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!isDemoMode ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Collapsible key={createKey} title="Register a source" icon={Plus} defaultOpen={createDefaultOpen}>
            <form className="space-y-4" onSubmit={onCreateSource}>
              <label className="block">
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  Display name
                </span>
                <input
                  value={formState.display_name}
                  onChange={(event) => onUpdateForm("display_name", event.target.value)}
                  className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  placeholder="Payments monorepo"
                />
              </label>

              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                    Kind
                  </span>
                  <select
                    value={formState.kind}
                    onChange={(event) => onUpdateForm("kind", event.target.value as SourceKind)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  >
                    {SOURCE_KIND_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>

                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                    Owner
                  </span>
                  <input
                    value={formState.owner}
                    onChange={(event) => onUpdateForm("owner", event.target.value)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                    placeholder="platform-security"
                  />
                </label>
              </div>

              {selectedKind.mode === "Read-only connector" ? (
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                    Connector name
                  </span>
                  <select
                    value={formState.connector_name}
                    onChange={(event) => onUpdateForm("connector_name", event.target.value)}
                    className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  >
                    <option value="">Choose connector…</option>
                    {connectorNames.map((connector) => (
                      <option key={connector} value={connector}>
                        {connector}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}

              <label className="block">
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                  Description
                </span>
                <textarea
                  value={formState.description}
                  onChange={(event) => onUpdateForm("description", event.target.value)}
                  rows={2}
                  className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                  placeholder={selectedKind.detail}
                />
              </label>

              <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
                <ModeChip mode={selectedKind.mode} />
                <p className="mt-2">{selectedKind.detail}</p>
              </div>

              <button
                type="submit"
                disabled={submitting || !canManageSources}
                className="inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {submitting ? "Creating…" : "Register source"}
              </button>
            </form>
          </Collapsible>

          <Collapsible title="Connector health" count={connectorHealth.length} defaultOpen={false} scrollMaxHeight="20rem">
            {connectorHealth.length === 0 && !loading ? (
              <p className="text-sm text-[color:var(--text-secondary)]">No connector health state loaded yet.</p>
            ) : (
              <div className="space-y-2">
                {connectorHealth.map((connector) => (
                  <div
                    key={connector.connector}
                    className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-[color:var(--foreground)]">{connector.connector}</h3>
                        <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">{connector.message}</p>
                      </div>
                      <SourceStatusPill status={connector.state} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Collapsible>
        </div>
      ) : null}

      <Collapsible
        title="Provider trust contracts"
        subtitle={
          providerContracts ? `${providerSummary.total} providers · v${providerContracts.contract_version}` : undefined
        }
        defaultOpen={false}
      >
        <div className="space-y-4">
          <p className="text-sm text-[color:var(--text-secondary)]">
            Backend provider registry: scan modes, declared permissions, and read-only guarantees.
          </p>
          <StatStrip
            items={[
              { label: "Providers", value: loading ? "…" : providerSummary.total },
              { label: "Read-only", value: loading ? "…" : `${providerSummary.readOnly}/${providerSummary.total}` },
              { label: "Scope-zero modes", value: loading ? "…" : providerSummary.scopeZero },
              { label: "Declared permissions", value: loading ? "…" : providerSummary.permissionCount },
            ]}
          />
          {providerContracts?.warnings?.length ? (
            <div className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
              {providerContracts.warnings.slice(0, 2).join(" · ")}
            </div>
          ) : null}
          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {!providerContracts && !loading ? (
              <div className="rounded-lg border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-sm text-[color:var(--text-secondary)]">
                Provider contracts are unavailable from the API.
              </div>
            ) : (
              (providerContracts?.providers ?? []).slice(0, 12).map((provider) => (
                <ProviderContractCard key={provider.name} provider={provider} />
              ))
            )}
          </div>
        </div>
      </Collapsible>

      {!isDemoMode ? (
        <Collapsible title="Related operating surfaces" defaultOpen={false}>
          <div className="grid gap-3 xl:grid-cols-2">
            {OPERATING_SURFACES.map((surface) => {
              const Icon = surface.icon;
              return (
                <Link key={surface.title} href={surface.href}>
                  <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 transition-colors hover:border-[color:var(--border-strong)]">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-2">
                          <Icon className="h-4 w-4 text-[color:var(--accent)]" />
                        </span>
                        <div>
                          <p className="text-sm font-semibold text-[color:var(--foreground)]">{surface.title}</p>
                          <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">{surface.summary}</p>
                        </div>
                      </div>
                      <ArrowRight className="mt-1 h-4 w-4 text-[color:var(--text-tertiary)]" />
                    </div>
                    <div className="mt-4 text-[11px] uppercase tracking-[0.18em] text-[color:var(--text-tertiary)]">
                      {surface.status}
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        </Collapsible>
      ) : null}
    </div>
  );
}

function SourceFilterToolbar({
  categoryCountsMap,
  statusChoices,
  filterCategory,
  onFilterCategory,
  filterStatus,
  onFilterStatus,
  filterQuery,
  onFilterQuery,
}: {
  categoryCountsMap: Record<SourceCategory | "all", number>;
  statusChoices: string[];
  filterCategory: SourceCategory | "all";
  onFilterCategory: (value: SourceCategory | "all") => void;
  filterStatus: string;
  onFilterStatus: (value: string) => void;
  filterQuery: string;
  onFilterQuery: (value: string) => void;
}) {
  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Source category">
        {SOURCE_CATEGORY_OPTIONS.map((category) => {
          const active = filterCategory === category.id;
          return (
            <button
              key={category.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => onFilterCategory(category.id)}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                active
                  ? "border-emerald-600/60 bg-emerald-500/10 text-[color:var(--foreground)]"
                  : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
              }`}
            >
              {category.label}
              <span className="text-[10px] text-[color:var(--text-tertiary)]">
                {categoryCountsMap[category.id] ?? 0}
              </span>
            </button>
          );
        })}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <label className="sr-only" htmlFor="source-status-filter">
          Status
        </label>
        <select
          id="source-status-filter"
          value={filterStatus}
          onChange={(event) => onFilterStatus(event.target.value)}
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-sm text-[color:var(--foreground)] outline-none transition focus:border-emerald-500"
        >
          <option value="all">All statuses</option>
          {statusChoices.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
        <label className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[color:var(--text-tertiary)]" />
          <input
            type="search"
            aria-label="Search sources"
            placeholder="Search sources…"
            value={filterQuery}
            onChange={(event) => onFilterQuery(event.target.value)}
            className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] py-1.5 pl-8 pr-3 text-sm text-[color:var(--foreground)] outline-none transition focus:border-emerald-500"
          />
        </label>
      </div>
    </div>
  );
}

function CategoryChip({ category }: { category: SourceCategory }) {
  const label = SOURCE_CATEGORY_OPTIONS.find((c) => c.id === category)?.label ?? category;
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${CATEGORY_CHIP_TONE[category]}`}>
      {label}
    </span>
  );
}

function UnifiedRow({
  row,
  connection,
  busyId,
  canManage,
  onOpen,
  onCloudTest,
  onCloudScan,
  onCloudDelete,
  onCloudScheduleChange,
}: {
  row: UnifiedSourceRow;
  connection: CloudConnectionRecord | null;
  busyId: string | null;
  canManage: boolean;
  onOpen: () => void;
  onCloudTest: (connection: CloudConnectionRecord) => void;
  onCloudScan: (connection: CloudConnectionRecord) => void;
  onCloudDelete: (connection: CloudConnectionRecord) => void;
  onCloudScheduleChange: (connection: CloudConnectionRecord, value: string) => void;
}) {
  const isCloud = row.origin === "cloud" && connection != null;
  const isBusy = isCloud ? busyId === connection!.id : false;
  const scannable = isCloud ? SCANNABLE_PROVIDERS.has(connection!.provider) : false;
  const mode = isCloud ? eventMode(connection!) : null;

  return (
    <tr className="group border-b border-[color:var(--border-subtle)] last:border-b-0 align-top">
      <td className="px-4 py-3">
        <button
          type="button"
          onClick={onOpen}
          title="View scan handoff, evidence, schedule, and actions"
          className="flex max-w-[260px] items-center gap-1 text-left"
        >
          <span
            className="truncate font-medium text-[var(--foreground)] transition-colors group-hover:text-emerald-400"
            title={row.name}
          >
            {row.name}
          </span>
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-[var(--text-tertiary)] opacity-0 transition group-hover:opacity-100" />
        </button>
        <p className="mt-0.5 max-w-[240px] truncate font-mono text-[11px] text-[var(--text-tertiary)]" title={row.detail}>
          {row.detail}
        </p>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col gap-1.5">
          <span className="inline-flex items-center gap-2 whitespace-nowrap text-[var(--text-secondary)]">
            {isCloud ? (
              <ProviderLogo provider={connection!.provider} className="h-4 w-4 shrink-0" />
            ) : null}
            {isCloud ? providerLabel(connection!.provider) : row.kindLabel}
          </span>
          <div className="flex items-center gap-1.5">
            <CategoryChip category={row.category} />
            {mode ? (
              <span
                className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${mode.tone}`}
                title={mode.detail}
              >
                <Clock className="h-2.5 w-2.5" />
                {mode.label}
              </span>
            ) : null}
          </div>
        </div>
      </td>
      <td className="px-4 py-3">
        {isCloud ? <StatusPill status={row.status} /> : <SourceStatusPill status={row.status} />}
      </td>
      <td className="whitespace-nowrap px-4 py-3 text-[var(--text-secondary)]">{formatWhen(row.lastScanAt)}</td>
      <td className="px-4 py-3">
        {isCloud ? (
          <>
            <label className="sr-only" htmlFor={`schedule-${connection!.id}`}>
              Scan schedule
            </label>
            <select
              id={`schedule-${connection!.id}`}
              value={connection!.scan_interval_minutes?.toString() ?? ""}
              disabled={!canManage}
              onChange={(event) => onCloudScheduleChange(connection!, event.target.value)}
              className="w-36 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1.5 text-xs text-[var(--foreground)] outline-none transition focus:border-emerald-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {SCHEDULE_OPTIONS.map(([label, value]) => (
                <option key={label} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </>
        ) : (
          <span className="tabular-nums text-[var(--text-secondary)]">
            {row.scheduleCount} schedule{row.scheduleCount === 1 ? "" : "s"}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        {isCloud ? (
          <div className="flex justify-end gap-2">
            <button
              onClick={() => onCloudTest(connection!)}
              disabled={isBusy || !canManage || !scannable}
              title={
                scannable
                  ? "Verify the stored read-only credential without running inventory"
                  : "Testing for this provider is unavailable"
              }
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-800/70 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-600 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              {isBusy ? "Working…" : "Test"}
            </button>
            <button
              onClick={() => onCloudScan(connection!)}
              disabled={isBusy || !canManage || !scannable}
              title={scannable ? "Run a read-only inventory and CIS scan" : "Scanning for this provider is unavailable"}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              {isBusy ? "Working…" : "Run scan"}
            </button>
            <button
              onClick={() => onCloudDelete(connection!)}
              disabled={isBusy || !canManage}
              aria-label={`Delete ${connection!.display_name}`}
              className="inline-flex items-center gap-1 rounded-lg border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 transition hover:bg-red-500/10 dark:hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete
            </button>
          </div>
        ) : (
          <div className="flex justify-end">
            <button
              type="button"
              onClick={onOpen}
              aria-label={`Open ${row.name}`}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              Manage
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </td>
    </tr>
  );
}

// ── Connect gallery ───────────────────────────────────────────────────────────

function CopyTextButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void copyTextToClipboard(text).then((ok) => {
          if (!ok) return;
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        });
      }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1 text-[11px] font-medium text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
    >
      <Copy className="h-3 w-3" />
      {copied ? "Copied" : label}
    </button>
  );
}

function GrantMethodPicker({
  method,
  onChange,
  provider,
}: {
  method: CloudGrantMethod;
  onChange: (method: CloudGrantMethod) => void;
  provider: string;
}) {
  return (
    <div className="space-y-2">
      <div
        className="inline-flex rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5"
        role="group"
        aria-label="Grant method"
      >
        {CLOUD_GRANT_METHODS.map((item) => (
          <button
            key={item}
            type="button"
            onClick={() => onChange(item)}
            className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
              method === item
                ? "bg-[color:var(--surface)] text-[color:var(--foreground)] shadow-sm"
                : "text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
            }`}
          >
            {cloudGrantMethodLabel(item)}
          </button>
        ))}
      </div>
      <p className="text-[10px] leading-4 text-[var(--text-tertiary)]">{cloudGrantMethodHint(method, provider)}</p>
    </div>
  );
}

function ConnectorGallery({
  activeCategory,
  onCategoryChange,
  search,
  onSearchChange,
  connectedCountFor,
  canManage,
  onConnectCloud,
  onRegisterSource,
  onConnectCodingAgent,
}: {
  activeCategory: ConnectorCategory | "all";
  onCategoryChange: (category: ConnectorCategory | "all") => void;
  search: string;
  onSearchChange: (value: string) => void;
  connectedCountFor: (connector: CatalogConnector) => number;
  canManage: boolean;
  onConnectCloud: (provider: string) => void;
  onRegisterSource: (kind: SourceKind) => void;
  onConnectCodingAgent: () => void;
}) {
  const query = search.trim().toLowerCase();
  const visible = CONNECTOR_CATALOG.filter((connector) => {
    const inCategory = activeCategory === "all" || connector.category === activeCategory;
    if (!inCategory) return false;
    if (!query) return true;
    const haystack = `${connector.label} ${connector.tagline} ${connector.keywords ?? ""}`.toLowerCase();
    return haystack.includes(query);
  });

  function categoryCount(category: ConnectorCategory | "all"): number {
    if (category === "all") return CONNECTOR_CATALOG.length;
    return CONNECTOR_CATALOG.filter((c) => c.category === category).length;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Connector category">
          {CONNECTOR_CATEGORIES.map((category) => {
            const active = activeCategory === category.id;
            return (
              <button
                key={category.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => onCategoryChange(category.id)}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                  active
                    ? "border-emerald-600/60 bg-emerald-500/10 text-[color:var(--foreground)]"
                    : "border-[color:var(--border-subtle)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
                }`}
              >
                {category.label}
                <span className="text-[10px] text-[color:var(--text-tertiary)]">{categoryCount(category.id)}</span>
              </button>
            );
          })}
        </div>
        <label className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[color:var(--text-tertiary)]" />
          <input
            type="search"
            aria-label="Search connectors"
            placeholder="Search connectors…"
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
            className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] py-1.5 pl-8 pr-3 text-sm text-[color:var(--foreground)] outline-none transition focus:border-emerald-500"
          />
        </label>
      </div>

      {visible.length === 0 ? (
        <p className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">
          No connectors match “{search}”.
        </p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {visible.map((connector) => (
            <ConnectorTile
              key={connector.id}
              connector={connector}
              connectedCount={connectedCountFor(connector)}
              canManage={canManage}
              onConnectCloud={onConnectCloud}
              onRegisterSource={onRegisterSource}
              onConnectCodingAgent={onConnectCodingAgent}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ConnectorTile({
  connector,
  connectedCount,
  canManage,
  onConnectCloud,
  onRegisterSource,
  onConnectCodingAgent,
}: {
  connector: CatalogConnector;
  connectedCount: number;
  canManage: boolean;
  onConnectCloud: (provider: string) => void;
  onRegisterSource: (kind: SourceKind) => void;
  onConnectCodingAgent: () => void;
}) {
  const Icon = connector.icon;
  const categoryLabel =
    CONNECTOR_CATEGORIES.find((c) => c.id === connector.category)?.label ?? connector.category;
  const connected = connectedCount > 0;

  return (
    <Card className="flex h-full flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[linear-gradient(145deg,var(--surface-elevated),var(--surface-muted))] shadow-inner shadow-black/20">
            {connector.logo ? (
              <ProviderLogo provider={connector.logo} className="h-6 w-6" />
            ) : (
              <Icon className="h-5 w-5 text-emerald-400" />
            )}
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-[var(--foreground)]">{connector.label}</p>
            <p className="truncate text-[11px] text-[var(--text-secondary)]">{connector.tagline}</p>
          </div>
        </div>
        <span
          className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium ${CONNECTOR_CATEGORY_TONE[connector.category]}`}
        >
          {categoryLabel}
        </span>
      </div>

      <div className="mt-auto flex items-center justify-between gap-2 pt-1">
        {connector.action.type === "coding-agent" ? (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-[color:var(--text-tertiary)]">
            <Lock className="h-3 w-3" /> Read-only
          </span>
        ) : connected ? (
          <span className="inline-flex items-center gap-1.5 text-[11px] text-emerald-300">
            <CheckCircle2 className="h-3 w-3" />
            {connectedCount} connected
          </span>
        ) : (
          <span className="text-[11px] text-[color:var(--text-tertiary)]">Not connected</span>
        )}

        {connector.action.type === "cloud" ? (
          <button
            type="button"
            onClick={() => onConnectCloud(connector.action.type === "cloud" ? connector.action.provider : "")}
            disabled={!canManage}
            aria-label={`Connect ${connector.label}`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Plug className="h-3.5 w-3.5" />
            Connect
          </button>
        ) : connector.action.type === "coding-agent" ? (
          <button
            type="button"
            onClick={onConnectCodingAgent}
            aria-label="Set up coding agent"
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/20"
          >
            <Plug className="h-3.5 w-3.5" />
            Set up
          </button>
        ) : (
          <button
            type="button"
            onClick={() => onRegisterSource(connector.action.type === "source" ? connector.action.sourceKind : "scan.repo")}
            disabled={!canManage}
            aria-label={`Register ${connector.label}`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-emerald-600 hover:text-emerald-700 dark:hover:text-emerald-300 disabled:cursor-not-allowed disabled:opacity-60"
          >
            Register
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </Card>
  );
}

// ── Coding-agent onboarding drawer ────────────────────────────────────────────

const CODING_AGENT_MCP_SNIPPET = `{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp-server"]
    }
  }
}`;

function CodingAgentDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Drawer
      open={open}
      onClose={onClose}
      size="lg"
      eyebrow="AI · Read-only"
      title="Connect a coding agent"
      subtitle={
        <span className="text-[11px] text-[color:var(--text-tertiary)]">
          Local MCP server + skills for Claude Code & Cursor
        </span>
      }
      headerAside={
        <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/30 px-2.5 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
          <Bot className="h-3 w-3" /> 73 MCP tools
        </span>
      }
    >
      <div className="space-y-4 text-sm text-[color:var(--text-secondary)]">
        <p>
          Expose Agent-BOM&apos;s read-only tools — scan, blast-radius, exposure-paths, SBOM, compliance, and
          remediation — to your coding agent over the Model Context Protocol. Everything runs locally against your
          control plane; no code or credentials leave your machine.
        </p>

        <section className="space-y-2">
          <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            <Terminal className="h-3.5 w-3.5" /> 1 · Start the MCP server
          </h3>
          <div className="flex items-center justify-between gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2">
            <code className="overflow-x-auto whitespace-nowrap font-mono text-[12px] text-[color:var(--foreground)]">
              agent-bom mcp-server
            </code>
            <CopyTextButton text="agent-bom mcp-server" />
          </div>
        </section>

        <section className="space-y-2">
          <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            <FileCode className="h-3.5 w-3.5" /> 2 · Register it in your agent
          </h3>
          <p className="text-[12px]">
            Add to your agent&apos;s MCP config (Claude Code <code className="font-mono">mcp.json</code>, Cursor{" "}
            <code className="font-mono">~/.cursor/mcp.json</code>):
          </p>
          <div className="relative">
            <pre className="overflow-x-auto rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3 font-mono text-[11px] leading-5 text-[color:var(--foreground)]">
              {CODING_AGENT_MCP_SNIPPET}
            </pre>
            <div className="mt-2">
              <CopyTextButton text={CODING_AGENT_MCP_SNIPPET} label="Copy config" />
            </div>
          </div>
        </section>

        <section className="space-y-2">
          <h3 className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
            <ShieldCheck className="h-3.5 w-3.5" /> Bundled skills
          </h3>
          <ul className="space-y-1.5 text-[12px]">
            <li className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span>
                <strong className="text-[color:var(--foreground)]">Cortex Code</strong> — scan-on-save, exposure-path
                lookups, and SBOM diffing inside your editor.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span>
                <strong className="text-[color:var(--foreground)]">OpenCLAW</strong> — agent-driven remediation and
                compliance workflows over the same read-only tools.
              </span>
            </li>
          </ul>
        </section>

        <p className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-900/50 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-2 text-[11px] text-emerald-700 dark:text-emerald-300">
          <Lock className="h-3.5 w-3.5 shrink-0" /> Read-only. The server never writes to your cloud, repos, or
          control-plane data.
        </p>
      </div>
    </Drawer>
  );
}

// ── Cloud connection detail drawer ────────────────────────────────────────────

function ConnectionDetailDrawer({
  connection,
  result,
  testResult,
  scanError,
  scheduleError,
  isBusy,
  canManage,
  scannable,
  onClose,
  onTest,
  onScan,
  onDelete,
}: {
  connection: CloudConnectionRecord | null;
  result: CloudConnectionScanResponse | undefined;
  testResult: CloudConnectionTestResponse | undefined;
  scanError: string | undefined;
  scheduleError: string | undefined;
  isBusy: boolean;
  canManage: boolean;
  scannable: boolean;
  onClose: () => void;
  onTest: (connection: CloudConnectionRecord) => void;
  onScan: (connection: CloudConnectionRecord) => void;
  onDelete: (connection: CloudConnectionRecord) => void;
}) {
  if (!connection) return null;
  const handoffScanId = result?.scan_id ?? connection.last_scan_id;
  const statusDetail = connection.status === "error" ? connection.status_detail : "";

  return (
    <Drawer
      open={Boolean(connection)}
      onClose={onClose}
      size="xl"
      eyebrow={providerLabel(connection.provider)}
      title={connection.display_name}
      subtitle={
        <span className="font-mono text-[11px] text-[color:var(--text-tertiary)]">{connection.role_ref}</span>
      }
      headerAside={<StatusPill status={connection.status} />}
      footer={
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => onTest(connection)}
            disabled={isBusy || !canManage || !scannable}
            className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-800/70 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <CheckCircle2 className="h-3.5 w-3.5" /> {isBusy ? "Working…" : "Test"}
          </button>
          <button
            onClick={() => onScan(connection)}
            disabled={isBusy || !canManage || !scannable}
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <ShieldCheck className="h-3.5 w-3.5" /> {isBusy ? "Working…" : "Run scan"}
          </button>
          <button
            onClick={() => onDelete(connection)}
            disabled={isBusy || !canManage}
            className="ml-auto inline-flex items-center gap-1 rounded-lg border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 transition hover:bg-red-500/10 dark:hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      }
    >
      <div className="space-y-3">
        {result ? <ScanResultPanel result={result} /> : null}
        {!result && testResult ? (
          <div className="rounded-xl border border-emerald-500/30 dark:border-emerald-900/60 bg-emerald-500/10 dark:bg-emerald-950/20 p-3 text-xs text-emerald-700 dark:text-emerald-200">
            Read-only credential verified. No inventory, CIS, findings, or resource writes ran.
          </div>
        ) : null}
        {!result && handoffScanId ? <ScanHandoffLinks scanId={handoffScanId} /> : null}
        {scanError ? (
          <div className="rounded-xl border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 p-3 text-xs text-red-700 dark:text-red-300">
            {scanError}
          </div>
        ) : null}
        {scheduleError ? (
          <div className="rounded-xl border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 p-3 text-xs text-red-700 dark:text-red-300">
            {scheduleError}
          </div>
        ) : null}
        {statusDetail ? (
          <div className="rounded-xl border border-amber-500/30 dark:border-amber-900/60 bg-amber-500/10 dark:bg-amber-950/20 p-3 text-xs text-amber-700 dark:text-amber-200">
            {statusDetail}
          </div>
        ) : null}
        {!result && !testResult && !handoffScanId && !scanError && !scheduleError && !statusDetail ? (
          <p className="text-sm text-[color:var(--text-secondary)]">
            No scan has run for this account yet. Use “Run scan” below to populate inventory, CIS results, and
            evidence links.
          </p>
        ) : null}
      </div>
    </Drawer>
  );
}

function ScanResultPanel({ result }: { result: CloudConnectionScanResponse }) {
  const { inventory, cis_benchmark: cis } = result;
  const isSnowflake = inventory.agent_count != null;
  const warnings = inventory.warnings ?? [];
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="inline-flex items-center gap-2 text-xs font-semibold text-[var(--foreground)]">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          Read-only scan complete
        </p>
        <span className="font-mono text-[10px] text-[var(--text-tertiary)]">scan {result.scan_id.slice(0, 8)}</span>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {isSnowflake ? (
          <StatTile icon={Boxes} label="Agents" value={String(inventory.agent_count ?? 0)} />
        ) : (
          <>
            <StatTile icon={Boxes} label="Resources" value={String(inventory.resource_count ?? 0)} />
            <StatTile icon={Fingerprint} label="Identities" value={String(inventory.identity_count ?? 0)} />
          </>
        )}
        <StatTile
          icon={CheckCircle2}
          label="CIS passed"
          value={cis.passed == null ? "—" : `${cis.passed}/${cis.total ?? "—"}`}
        />
        <StatTile icon={KeyRound} label="CIS pass rate" value={formatPassRate(cis.pass_rate)} />
      </div>
      {warnings.length > 0 ? (
        <p className="mt-3 text-[11px] leading-5 text-amber-300">{warnings.join(" · ")}</p>
      ) : null}
      <p className="mt-3 text-[11px] leading-5 text-[var(--text-tertiary)]">{result.audit_metadata.note}</p>
      <div className="mt-4 flex flex-wrap gap-2">
        {evidenceLinks(result.scan_id).map(({ label, href, icon: Icon }) => (
          <HandoffLink key={label} label={label} href={href} icon={Icon} />
        ))}
      </div>
    </div>
  );
}

function ScanHandoffLinks({ scanId }: { scanId: string }) {
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="inline-flex items-center gap-2 text-xs font-semibold text-[var(--foreground)]">
          <FileSearch className="h-4 w-4 text-emerald-400" />
          Last scan handoff
        </p>
        <span className="font-mono text-[10px] text-[var(--text-tertiary)]">scan {scanId.slice(0, 8)}</span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {evidenceLinks(scanId).map(({ label, href, icon }) => (
          <HandoffLink key={label} label={label} href={href} icon={icon} />
        ))}
      </div>
    </div>
  );
}

function HandoffLink({
  label,
  href,
  icon: Icon,
}: {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <Link
      href={href}
      className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--foreground)] transition hover:border-emerald-700 hover:text-emerald-700 dark:hover:text-emerald-300"
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </Link>
  );
}

function StatTile({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3">
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
        <Icon className="h-3.5 w-3.5 text-emerald-400" />
        {label}
      </div>
      <p className="mt-1.5 text-lg font-semibold text-[var(--foreground)]">{value}</p>
    </div>
  );
}

// ── Source detail drawer ──────────────────────────────────────────────────────

function SourceDrawer({
  source,
  open,
  onClose,
  schedules,
  busySourceId,
  busyScheduleId,
  canManageSources,
  canRunScans,
  onSourceAction,
  onScheduleAction,
  onCreateSchedule,
  submittingSchedule,
  scheduleName,
  scheduleCron,
  onScheduleNameChange,
  onScheduleCronChange,
}: {
  source: SourceRecord | null;
  open: boolean;
  onClose: () => void;
  schedules: ScanSchedule[];
  busySourceId: string | null;
  busyScheduleId: string | null;
  canManageSources: boolean;
  canRunScans: boolean;
  onSourceAction: (sourceId: string, action: "test" | "run" | "delete") => void;
  onScheduleAction: (scheduleId: string, action: "toggle" | "delete") => void;
  onCreateSchedule: (event: React.FormEvent<HTMLFormElement>, source: SourceRecord) => void;
  submittingSchedule: boolean;
  scheduleName: string;
  scheduleCron: string;
  onScheduleNameChange: (value: string) => void;
  onScheduleCronChange: (value: string) => void;
}) {
  if (!source) return null;
  const option = kindOption(source.kind);
  const mode = option?.mode ?? "Direct scan";
  const isBusy = busySourceId === source.source_id;
  const schedulable = SCHEDULABLE_KINDS.has(source.kind);

  const meta: [string, React.ReactNode][] = [
    ["Owner", source.owner || "Unassigned"],
    ["Credential mode", source.credential_mode],
    ["Connector", source.connector_name || "—"],
    ["Enabled", source.enabled ? "Enabled" : "Disabled"],
    ["Last tested", formatWhen(source.last_tested_at)],
    ["Last run", formatWhen(source.last_run_at)],
  ];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      eyebrow={mode}
      title={source.display_name}
      subtitle={option?.label ?? source.kind}
      headerAside={<SourceStatusPill status={source.status} />}
      size="2xl"
      ariaLabel={`Source ${source.display_name}`}
      footer={
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onSourceAction(source.source_id, "test")}
            disabled={isBusy || !canManageSources}
            className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isBusy ? "Working…" : "Test"}
          </button>
          <button
            onClick={() => onSourceAction(source.source_id, "run")}
            disabled={isBusy || !source.enabled || !canRunScans}
            className="rounded-lg bg-[color:var(--accent)] px-3 py-2 text-xs font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Run now
          </button>
          <button
            onClick={() => onSourceAction(source.source_id, "delete")}
            disabled={isBusy || !canManageSources}
            className="rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-xs font-medium text-[color:var(--status-danger)] transition hover:border-[color:var(--status-danger)] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Delete
          </button>
        </div>
      }
    >
      <div className="space-y-5" data-testid={`source-detail-${source.source_id}`}>
        {source.description ? (
          <p className="text-sm leading-6 text-[color:var(--text-secondary)]">{source.description}</p>
        ) : null}

        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
          {meta.map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{label}</dt>
              <dd className="mt-0.5 truncate text-[color:var(--text-secondary)]">{value}</dd>
            </div>
          ))}
          <div className="col-span-2 min-w-0">
            <dt className="text-[11px] uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">Last job</dt>
            <dd className="mt-0.5">
              {source.last_job_id ? (
                <Link
                  href={`/scan?id=${encodeURIComponent(source.last_job_id)}`}
                  className="inline-block max-w-full truncate font-mono text-[color:var(--accent)] hover:underline"
                  title={source.last_job_id}
                >
                  {formatShortId(source.last_job_id)}
                </Link>
              ) : (
                <span className="text-[color:var(--text-secondary)]">—</span>
              )}
            </dd>
          </div>
        </dl>

        {source.last_test_message ? (
          <p className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3 text-xs leading-5 text-[color:var(--text-secondary)]">
            {source.last_test_message}
          </p>
        ) : null}

        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
          <div className="flex items-start gap-2">
            <FileCheck2 className="mt-0.5 h-4 w-4 text-[color:var(--accent)]" />
            <div>
              <p className="text-xs font-semibold text-[color:var(--foreground)]">Evidence workflow</p>
              <p className="mt-1 text-xs leading-5 text-[color:var(--text-secondary)]">
                {source.last_job_id
                  ? "Open the completed job surfaces created from this source."
                  : "Run this source to create findings, graph, and compliance evidence."}
              </p>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {[
              { target: "jobs" as const, label: "Jobs" },
              { target: "findings" as const, label: "Findings" },
              { target: "graph" as const, label: "Graph" },
              { target: "compliance" as const, label: "Compliance" },
            ].map((link) => {
              const disabled = link.target !== "jobs" && !source.last_job_id;
              return (
                <Link
                  key={link.target}
                  href={sourceEvidenceHref(source, link.target)}
                  aria-disabled={disabled}
                  className={`rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition ${
                    disabled
                      ? "pointer-events-none border-[color:var(--border-subtle)] text-[color:var(--text-tertiary)] opacity-60"
                      : "border-[color:var(--border-subtle)] text-[color:var(--foreground)] hover:border-[color:var(--border-strong)]"
                  }`}
                >
                  {link.label}
                </Link>
              );
            })}
          </div>
        </div>

        <div>
          <h3 className="text-sm font-semibold text-[color:var(--foreground)]">Schedules</h3>
          <div className="mt-3 space-y-2">
            {schedules.length === 0 ? (
              <p className="text-xs text-[color:var(--text-secondary)]">No schedules bound to this source yet.</p>
            ) : (
              schedules.map((schedule) => {
                const isScheduleBusy = busyScheduleId === schedule.schedule_id;
                return (
                  <div
                    key={schedule.schedule_id}
                    className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-[color:var(--foreground)]">{schedule.name}</p>
                        <p className="mt-0.5 font-mono text-xs text-[color:var(--text-secondary)]">
                          {schedule.cron_expression}
                        </p>
                      </div>
                      <SourceStatusPill status={schedule.enabled ? "active" : "paused"} />
                    </div>
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-[color:var(--text-secondary)]">
                      <span>Next: {formatWhen(schedule.next_run)}</span>
                      <span>Last: {formatWhen(schedule.last_run)}</span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        onClick={() => onScheduleAction(schedule.schedule_id, "toggle")}
                        disabled={isScheduleBusy || !canManageSources}
                        className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {isScheduleBusy ? "Working…" : schedule.enabled ? "Pause" : "Enable"}
                      </button>
                      <button
                        onClick={() => onScheduleAction(schedule.schedule_id, "delete")}
                        disabled={isScheduleBusy || !canManageSources}
                        className="rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-1.5 text-xs font-medium text-[color:var(--status-danger)] transition hover:border-[color:var(--status-danger)] disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })
            )}

            {schedulable ? (
              <form
                className="rounded-lg border border-dashed border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
                onSubmit={(event) => onCreateSchedule(event, source)}
              >
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="block">
                    <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                      Name
                    </span>
                    <input
                      aria-label="Schedule name"
                      value={scheduleName}
                      onChange={(event) => onScheduleNameChange(event.target.value)}
                      className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                      placeholder="Nightly posture"
                    />
                  </label>
                  <label className="block">
                    <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">
                      Cron
                    </span>
                    <input
                      aria-label="Schedule cron"
                      value={scheduleCron}
                      onChange={(event) => onScheduleCronChange(event.target.value)}
                      className="w-full rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-3 py-2 font-mono text-sm text-[color:var(--foreground)] outline-none transition focus:border-[color:var(--accent-border)]"
                      placeholder="0 * * * *"
                    />
                  </label>
                </div>
                <button
                  type="submit"
                  disabled={submittingSchedule || !canManageSources}
                  className="mt-3 inline-flex items-center gap-2 rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] transition hover:bg-[color:var(--accent-strong)] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <CalendarClock className="h-4 w-4" />
                  {submittingSchedule ? "Creating…" : "Create schedule"}
                </button>
              </form>
            ) : null}
          </div>
        </div>
      </div>
    </Drawer>
  );
}

function ProviderContractCard({ provider }: { provider: DiscoveryProviderContract }) {
  const trust = provider.trust_contract;
  const capabilities = provider.capabilities;
  const destinations = capabilities.network_destinations ?? capabilities.outbound_destinations;
  const permissions = capabilities.permissions_used;
  const scanModes = capabilities.scan_modes;
  const previewModes = scanModes.slice(0, 3);
  const extraModeCount = scanModes.length - previewModes.length;

  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-[color:var(--foreground)]">{provider.name}</h3>
          <p className="mt-1 truncate font-mono text-[11px] text-[color:var(--text-tertiary)]">{provider.source}</p>
        </div>
        <span
          className="shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-medium"
          style={
            trust.supports_scope_zero
              ? {
                  borderColor: "var(--status-success-border)",
                  backgroundColor: "var(--status-success-bg)",
                  color: "var(--status-success)",
                }
              : {
                  borderColor: "var(--border-subtle)",
                  backgroundColor: "var(--surface)",
                  color: "var(--text-secondary)",
                }
          }
        >
          {trust.supports_scope_zero ? "scope-zero" : "direct pull"}
        </span>
      </div>

      <div className="mt-3 flex max-h-14 flex-wrap gap-1.5 overflow-hidden">
        {previewModes.map((mode) => (
          <span
            key={mode}
            className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] font-mono text-[color:var(--text-secondary)]"
          >
            {formatMode(mode)}
          </span>
        ))}
        {extraModeCount > 0 ? (
          <span
            className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2 py-0.5 text-[10px] font-medium text-[color:var(--text-tertiary)]"
            title={scanModes.slice(3).map(formatMode).join(", ")}
          >
            +{extraModeCount} mode{extraModeCount === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>

      <div className="mt-4 grid gap-2 text-xs text-[color:var(--text-secondary)] sm:grid-cols-2">
        <span>Read-only: {trust.read_only ? "yes" : "no"}</span>
        <span>Agentless: {trust.agentless ? "yes" : "no"}</span>
        <span>Redaction: {formatMode(trust.redaction_status)}</span>
        <span>Residency: {formatMode(trust.data_residency)}</span>
      </div>

      <div className="mt-4 space-y-2 text-xs text-[color:var(--text-secondary)]">
        <div>
          <span className="text-[color:var(--text-tertiary)]">Permissions used: </span>
          <span className="text-[color:var(--foreground)]">{permissions.length}</span>
          {permissions.length > 0 ? (
            <span className="ml-1 font-mono text-[11px] text-[color:var(--text-secondary)]">
              {permissions.slice(0, 3).join(", ")}
              {permissions.length > 3 ? ` +${permissions.length - 3}` : ""}
            </span>
          ) : null}
        </div>
        <div>
          <span className="text-[color:var(--text-tertiary)]">Network: </span>
          <span className="font-mono text-[11px] text-[color:var(--text-secondary)]">
            {destinations.length ? destinations.slice(0, 3).join(", ") : "none"}
            {destinations.length > 3 ? ` +${destinations.length - 3}` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── Add connection wizard ─────────────────────────────────────────────────────

interface WizardForm {
  provider: string;
  display_name: string;
  role_ref: string;
  external_id: string;
  regions: string;
  auth: Record<string, string>;
}

function buildWizardForm(provider: string): WizardForm {
  return {
    provider,
    display_name: "",
    role_ref: "",
    external_id: "",
    regions: "",
    auth: {},
  };
}

function AddConnectionWizard({
  initialProvider,
  onClose,
  onCreated,
}: {
  initialProvider?: string | undefined;
  onClose: () => void;
  onCreated: (created: CloudConnectionRecord) => void;
}) {
  const [step, setStep] = useState<0 | 1 | 2>(0);
  const [form, setForm] = useState<WizardForm>(() =>
    buildWizardForm(initialProvider && providerOption(initialProvider) ? initialProvider : "aws"),
  );
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [generatedExternalId, setGeneratedExternalId] = useState("");
  const [grantMethod, setGrantMethod] = useState<CloudGrantMethod>("cli");

  const provider = useMemo(
    () => providerOption(form.provider) ?? PROVIDER_OPTIONS[0]!,
    [form.provider],
  );

  const isAws = provider.value === "aws";

  useEffect(() => {
    if (!isAws) return;
    setGeneratedExternalId((current) => current || generateConnectionExternalId());
  }, [isAws]);

  useEffect(() => {
    if (!isAws || !generatedExternalId) return;
    setForm((current) =>
      current.external_id === generatedExternalId
        ? current
        : { ...current, external_id: generatedExternalId },
    );
  }, [isAws, generatedExternalId]);

  function update<K extends keyof WizardForm>(field: K, value: WizardForm[K]) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  function updateAuth(key: string, value: string) {
    setForm((current) => ({ ...current, auth: { ...current.auth, [key]: value } }));
  }

  function selectProvider(value: string) {
    setForm((current) => {
      if (current.provider === value) return current;
      setGeneratedExternalId("");
      return {
        ...current,
        provider: value,
        role_ref: "",
        external_id: "",
        regions: "",
        auth: {},
      };
    });
  }

  function goNext() {
    setStep((current) => (current + 1) as 0 | 1 | 2);
  }

  function handleRegenerateExternalId() {
    const value = generateConnectionExternalId();
    setGeneratedExternalId(value);
    setForm((current) => ({ ...current, external_id: value }));
  }

  const providerMeta = cloudProviderMeta(provider.value);
  const deployScript = buildGrantScript(
    provider.value,
    grantMethod,
    isAws ? generatedExternalId || undefined : undefined,
  );

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);

    const displayName = form.display_name.trim();
    const roleRef = form.role_ref.trim();
    const externalId = form.external_id;
    const regions = provider.usesRegions
      ? form.regions
          .split(/[\s,]+/)
          .map((region) => region.trim())
          .filter(Boolean)
      : [];

    if (!displayName) {
      setFormError("A display name is required.");
      return;
    }
    if (!roleRef) {
      setFormError(`${provider.roleField.label} is required.`);
      return;
    }
    const authParams: Record<string, string> = {};
    for (const field of provider.authFields) {
      const value = (form.auth[field.key] ?? "").trim();
      if (!value) {
        setFormError(`${field.label} is required.`);
        return;
      }
      authParams[field.key] = value;
    }
    if (!externalId.trim()) {
      setFormError(`${provider.secretField.label} is required.`);
      return;
    }

    const payload: CloudConnectionCreateRequest = {
      provider: form.provider,
      display_name: displayName,
      role_ref: roleRef,
      external_id: externalId,
      regions,
      auth_params: authParams,
    };

    setSubmitting(true);
    try {
      const created = await api.createCloudConnection(payload);
      setForm((current) => ({ ...current, external_id: "" }));
      onCreated(created);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to create connection.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-[80] flex items-start justify-center overflow-y-auto bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Add cloud account"
      onClick={onClose}
    >
      <div
        className="my-8 w-full max-w-xl rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] shadow-2xl shadow-black/40"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-[color:var(--border-subtle)] px-5 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]">
              <ProviderLogo provider={provider.value} className="h-5 w-5" />
            </span>
            <div>
              <h2 className="text-base font-semibold text-[var(--foreground)]">Add cloud account</h2>
              <p className="text-xs text-[var(--text-secondary)]">Read-only connection · step {step + 1} of 3</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-1.5 text-[var(--text-secondary)] transition hover:bg-[color:var(--surface-elevated)] hover:text-[var(--foreground)]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="space-y-5 px-5 py-5">
            <StepIndicator step={step} />

            {step === 0 ? (
              <fieldset className="space-y-3">
                <legend className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                  Choose a provider
                </legend>
                <div className="grid gap-2 sm:grid-cols-2">
                  {PROVIDER_OPTIONS.map((option) => {
                    const selected = form.provider === option.value;
                    return (
                      <button
                        type="button"
                        key={option.value}
                        onClick={() => selectProvider(option.value)}
                        aria-pressed={selected}
                        className={`flex items-center gap-3 rounded-xl border p-3 text-left transition ${
                          selected
                            ? "border-emerald-500 bg-emerald-950/20"
                            : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] hover:border-[color:var(--border-strong)]"
                        }`}
                      >
                        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)]">
                          <ProviderLogo provider={option.value} className="h-5 w-5" />
                        </span>
                        <span className="min-w-0">
                          <span className="block text-sm font-medium text-[var(--foreground)]">{option.label}</span>
                          <span className="mt-0.5 block text-[11px] text-[var(--text-secondary)]">{option.tagline}</span>
                          {cloudProviderMeta(option.value) ? (
                            <span className="mt-1 block text-[10px] uppercase tracking-[0.12em] text-purple-300/80">
                              Read-only broker
                            </span>
                          ) : null}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </fieldset>
            ) : null}

            {step === 1 ? (
              <div className="space-y-3">
                <p className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                  Grant read-only access
                </p>
                <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-xs leading-6 text-[var(--text-secondary)]">
                  <p className="text-[var(--foreground)]">
                    Run this in your {provider.label} to create the read-only grant, then paste the{" "}
                    {provider.roleField.label.toLowerCase()} in the next step.
                  </p>
                  <div className="mt-4 space-y-2">
                    <GrantMethodPicker method={grantMethod} onChange={setGrantMethod} provider={provider.value} />
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">
                        {cloudGrantMethodLabel(grantMethod)} grant script
                      </p>
                      {deployScript ? <CopyTextButton text={deployScript} label="Copy script" /> : null}
                    </div>
                    <pre className="max-h-40 overflow-auto rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-2.5 font-mono text-[10px] leading-5 text-[var(--foreground)]">
                      {deployScript || provider.cli}
                    </pre>
                  </div>
                  {isAws ? (
                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-emerald-900/50 bg-emerald-950/20 px-2.5 py-2">
                      <div className="min-w-0">
                        <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-emerald-200/80">
                          ExternalId (embedded in the script above)
                        </p>
                        {generatedExternalId ? (
                          <p data-testid="wizard-external-id" className="break-all font-mono text-[11px] text-[var(--foreground)]">
                            {generatedExternalId}
                          </p>
                        ) : null}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {generatedExternalId ? <CopyTextButton text={generatedExternalId} label="Copy" /> : null}
                        <button
                          type="button"
                          onClick={handleRegenerateExternalId}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500"
                        >
                          <RefreshCcw className="h-3 w-3" />
                          Regenerate
                        </button>
                      </div>
                    </div>
                  ) : null}
                  <Collapsible
                    title="How this works & security"
                    defaultOpen={false}
                    bare
                    className="mt-3"
                    titleClassName="text-[11px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]"
                  >
                    <ul className="mt-2 space-y-1 text-[11px] text-[var(--text-secondary)]">
                      {providerMeta?.deployNotes.map((note) => (
                        <li key={note} className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          {note}
                        </li>
                      ))}
                      {isAws ? (
                        <li className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          The ExternalId is embedded in the grant script and is what the connection stores — it carries
                          to the next step unchanged. Regenerate only before you apply the grant.
                        </li>
                      ) : null}
                      <li className="flex items-start gap-1.5">
                        <Lock className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                        The {provider.secretField.label.toLowerCase()} is stored encrypted at rest and never displayed
                        again.
                      </li>
                    </ul>
                  </Collapsible>
                </div>
              </div>
            ) : null}

            {step === 2 ? (
              <div className="space-y-4">
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                    Display name
                  </span>
                  <input
                    value={form.display_name}
                    onChange={(event) => update("display_name", event.target.value)}
                    placeholder="Production account"
                    className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                    {provider.roleField.label}
                  </span>
                  <input
                    value={form.role_ref}
                    onChange={(event) => update("role_ref", event.target.value)}
                    placeholder={provider.roleField.placeholder}
                    className={`w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500 ${provider.roleField.mono ? "font-mono" : ""}`}
                  />
                </label>
                {provider.authFields.map((field) => (
                  <label key={field.key} className="block">
                    <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                      {field.label}
                    </span>
                    <input
                      value={form.auth[field.key] ?? ""}
                      onChange={(event) => updateAuth(field.key, event.target.value)}
                      placeholder={field.placeholder}
                      className={`w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500 ${field.mono ? "font-mono" : ""}`}
                    />
                  </label>
                ))}
                <label className="block">
                  <span className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                      {provider.secretField.label}
                    </span>
                    {isAws ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-300">
                        <CheckCircle2 className="h-3 w-3" /> Carried from setup
                      </span>
                    ) : null}
                  </span>
                  {isAws ? (
                    <div className="flex items-center justify-between gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2">
                      <code data-testid="wizard-external-id-details" className="min-w-0 break-all font-mono text-sm text-[var(--foreground)]">
                        {form.external_id}
                      </code>
                      <CopyTextButton text={form.external_id} label="Copy" />
                    </div>
                  ) : provider.secretField.multiline ? (
                    <textarea
                      autoComplete="off"
                      rows={5}
                      value={form.external_id}
                      onChange={(event) => update("external_id", event.target.value)}
                      placeholder={provider.secretField.placeholder}
                      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-xs text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                    />
                  ) : (
                    <input
                      type="password"
                      autoComplete="off"
                      value={form.external_id}
                      onChange={(event) => update("external_id", event.target.value)}
                      placeholder={provider.secretField.placeholder}
                      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                    />
                  )}
                  <span className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)]">
                    <Lock className="h-3 w-3" />{" "}
                    {isAws
                      ? "Matches the ExternalId in your trust policy. Stored encrypted at rest; regenerate on the Setup step only if you have not applied the grant yet."
                      : provider.secretField.hint}
                  </span>
                </label>
                {provider.usesRegions ? (
                  <label className="block">
                    <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                      Regions (optional)
                    </span>
                    <input
                      value={form.regions}
                      onChange={(event) => update("regions", event.target.value)}
                      placeholder="us-east-1, us-west-2"
                      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                    />
                  </label>
                ) : null}
              </div>
            ) : null}

            {formError ? <p className="text-sm text-red-400">{formError}</p> : null}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-[color:var(--border-subtle)] px-5 py-4">
            <button
              type="button"
              onClick={() => (step === 0 ? onClose() : setStep((s) => (s - 1) as 0 | 1 | 2))}
              className="inline-flex items-center gap-1.5 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              {step === 0 ? (
                "Cancel"
              ) : (
                <>
                  <ArrowLeft className="h-4 w-4" /> Back
                </>
              )}
            </button>
            {step < 2 ? (
              <button
                key="wizard-next"
                type="button"
                onClick={goNext}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400"
              >
                Next <ArrowRight className="h-4 w-4" />
              </button>
            ) : (
              <button
                key="wizard-submit"
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {submitting ? "Connecting…" : "Create connection"}
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}

function StepIndicator({ step }: { step: number }) {
  const labels = ["Provider", "Setup", "Details"];
  return (
    <div className="flex items-center gap-2">
      {labels.map((label, index) => (
        <div key={label} className="flex flex-1 items-center gap-2">
          <span
            className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold ${
              index <= step
                ? "border-emerald-500 bg-emerald-500 text-black"
                : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[var(--text-tertiary)]"
            }`}
          >
            {index + 1}
          </span>
          <span className={`text-xs ${index <= step ? "text-[var(--foreground)]" : "text-[var(--text-tertiary)]"}`}>
            {label}
          </span>
          {index < labels.length - 1 ? <span className="h-px flex-1 bg-[color:var(--border-subtle)]" /> : null}
        </div>
      ))}
    </div>
  );
}
