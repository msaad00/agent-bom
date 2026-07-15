"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
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
} from "lucide-react";

import {
  api,
  type CloudConnectionRecord,
  type CloudConnectionCreateRequest,
  type CloudConnectionTestResponse,
  type CloudConnectionScanResponse,
  type SourceRecord,
} from "@/lib/api";
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
import { RUN_SCAN_ACTION } from "@/lib/empty-state-actions";
import { vendorLogo } from "@/lib/vendor-logos";
import { FirstRunJourney } from "@/components/first-run-journey";
import {
  PermissionDeniedNotice,
  RoleBadge,
  RolePermissionsPanel,
} from "@/components/role-access";

// ── Provider catalog ──────────────────────────────────────────────────────────
// Every option maps its wizard fields onto the connection's role_ref (plaintext
// principal ref), external_id (the one write-only secret), and auth_params
// (non-secret provider params). `permissions` / `cli` mirror the real
// `agent-bom connect <provider>` onboarding (src/agent_bom/cli/_entry_points.py).
//
// `readiness` reflects the API's broker-enabled scan runners for AWS, Azure,
// GCP, and Snowflake.

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
  /** Read-only role/identity grant this connection assumes (from `agent-bom connect`). */
  permissions: string;
  /** The exact onboarding CLI for this provider. */
  cli: string;
  /** Phase A brokering maturity for the readiness badge. */
  readiness: ProviderReadiness;
  /** Maps to role_ref (plaintext principal/account reference). */
  roleField: ProviderField;
  /** Map to auth_params (non-secret provider params). */
  authFields: ProviderField[];
  /** Maps to external_id (the single write-only secret). */
  secretField: ProviderField & { multiline?: boolean; hint: string };
  /** Whether regions apply (AWS only). */
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

const SCANNABLE_PROVIDERS = new Set(
  PROVIDER_OPTIONS.map((option) => option.value),
);

// ── Connector catalog ─────────────────────────────────────────────────────────
// One scalable, filterable gallery over every connectable surface. Cloud tiles
// open the read-only AddConnectionWizard; source tiles deep-link into the Data
// Sources register hub for that kind; the coding-agent tile opens the local
// MCP-server / skills onboarding drawer. Adding a surface = one array entry.

type ConnectorCategory = "cloud" | "code" | "ai" | "data";

type ConnectorAction =
  | { type: "cloud"; provider: string }
  | { type: "source"; href: string; sourceKind: string }
  | { type: "coding-agent" };

interface CatalogConnector {
  id: string;
  category: ConnectorCategory;
  label: string;
  tagline: string;
  /** vendor id for ProviderLogo, when a brand mark exists. */
  logo?: string;
  icon: React.ComponentType<{ className?: string }>;
  /** extra free-text search terms (ecosystems, aliases). */
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
    action: { type: "source", href: "/sources", sourceKind: "scan.repo" },
  },
  {
    id: "image",
    category: "code",
    label: "Container images",
    tagline: "Image & OS package scan",
    icon: Container,
    keywords: "docker oci containers registry trivy os packages",
    action: { type: "source", href: "/sources", sourceKind: "scan.image" },
  },
  {
    id: "iac",
    category: "code",
    label: "IaC & clusters",
    tagline: "Terraform & Kubernetes scan",
    icon: FileCode,
    keywords: "terraform k8s kubernetes helm iac misconfiguration",
    action: { type: "source", href: "/sources", sourceKind: "scan.iac" },
  },
  {
    id: "registry",
    category: "code",
    label: "Package registry",
    tagline: "Read-only registry connector",
    icon: Package,
    keywords: "npm pypi maven artifactory ghcr registry connector",
    action: { type: "source", href: "/sources", sourceKind: "connector.registry" },
  },
  {
    id: "mcp",
    category: "ai",
    label: "MCP configs",
    tagline: "Local MCP configuration scan",
    icon: Plug,
    keywords: "model context protocol mcp servers tools aispm",
    action: { type: "source", href: "/sources", sourceKind: "scan.mcp_config" },
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
    action: { type: "source", href: "/sources", sourceKind: "connector.warehouse" },
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

/** Compact date (e.g. "Jul 14") for KPI tiles where a full timestamp overflows. */
function formatWhenShort(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
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

function formatPassRate(rate: number | null): string {
  if (rate == null) return "—";
  // pass_rate may be 0–1 or 0–100 depending on the benchmark; normalize to a percent.
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

// ── Brand mark + readiness ────────────────────────────────────────────────────

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
    // Brand SVGs are static assets served from /logos; next/image optimization is
    // disabled in this app (next.config images.unoptimized), so a plain img is
    // the lightest correct render.
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={src}
      alt={`${providerLabel(provider)} logo`}
      className={`${className} object-contain`}
    />
  );
}

export default function ConnectionsPage() {
  const { hasCapability, session } = useAuthState();
  const { counts } = useDeploymentContext();
  const canManage = !session?.auth_required || hasCapability("scan.run");
  const cloudService = serviceEntry(counts?.services, "cloud_accounts");

  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardProvider, setWizardProvider] = useState<string | undefined>(
    undefined,
  );
  const [busyId, setBusyId] = useState<string | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<
    Record<string, CloudConnectionScanResponse>
  >({});
  const [scanErrors, setScanErrors] = useState<Record<string, string>>({});
  const [testResults, setTestResults] = useState<
    Record<string, CloudConnectionTestResponse>
  >({});
  const [scheduleErrors, setScheduleErrors] = useState<Record<string, string>>(
    {},
  );
  const [sources, setSources] = useState<SourceRecord[]>([]);
  const [galleryCategory, setGalleryCategory] = useState<ConnectorCategory | "all">("all");
  const [gallerySearch, setGallerySearch] = useState("");
  const [codingAgentOpen, setCodingAgentOpen] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listCloudConnections();
      setConnections(result.connections);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to load cloud connections.",
      );
      setConnections([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    let mounted = true;
    api
      .listSources()
      .then((response) => {
        if (mounted) setSources(response.sources ?? []);
      })
      .catch(() => {
        if (mounted) setSources([]);
      });
    return () => {
      mounted = false;
    };
  }, []);

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
      const detail =
        err instanceof Error ? err.message : "Connection test failed.";
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
      setError(
        err instanceof Error ? err.message : "Failed to delete connection.",
      );
    } finally {
      setBusyId(null);
    }
  }

  async function handleScheduleChange(
    connection: CloudConnectionRecord,
    value: string,
  ) {
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
      setConnections((prev) =>
        prev.map((item) => (item.id === updated.id ? updated : item)),
      );
      setMessage(`${updated.display_name} scan schedule updated.`);
    } catch (err) {
      const detail =
        err instanceof Error ? err.message : "Failed to update schedule.";
      setScheduleErrors((prev) => ({ ...prev, [connection.id]: detail }));
    }
  }

  const activeCount = useMemo(
    () => connections.filter((c) => c.status === "active").length,
    [connections],
  );

  const lastAccountScan = useMemo(() => {
    const stamps = connections
      .map((c) => c.last_scan_at)
      .filter((v): v is string => Boolean(v))
      .sort((a, b) => b.localeCompare(a));
    return stamps[0] ?? null;
  }, [connections]);

  const hasConnections = connections.length > 0;

  const connectedByProvider = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const connection of connections) {
      counts[connection.provider] = (counts[connection.provider] ?? 0) + 1;
    }
    return counts;
  }, [connections]);

  const sourceCountByKind = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const source of sources) {
      counts[source.kind] = (counts[source.kind] ?? 0) + 1;
    }
    return counts;
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

  const gallery = (
    <ConnectorGallery
      activeCategory={galleryCategory}
      onCategoryChange={setGalleryCategory}
      search={gallerySearch}
      onSearchChange={setGallerySearch}
      connectedCountFor={connectorConnectedCount}
      canManage={canManage}
      onConnectCloud={openWizard}
      onConnectCodingAgent={() => setCodingAgentOpen(true)}
    />
  );

  return (
    <div className="space-y-6">
      <PageLaneHeader
        lane="cloud-data"
        title="Connections"
        subtitle="Connect cloud accounts, code, AI, and data sources — read-only, with secrets encrypted at rest."
        scopeChip={
          <span className="inline-flex items-center rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-[11px] font-medium text-purple-700 dark:text-purple-200">
            {deploymentModeLabel(counts?.deployment_mode)} · brokered read-only
          </span>
        }
        actions={
          <>
            <button
              onClick={() => void refresh()}
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
            <Link
              href="/sources"
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-4 py-2 text-sm text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
            >
              <Boxes className="h-4 w-4" />
              Data sources
            </Link>
          </>
        }
        banner={
          <div className="grid gap-3 sm:grid-cols-3">
            <StatCard label="Connections" value={loading ? "…" : connections.length} />
            <StatCard label="Active" value={loading ? "…" : activeCount} accent="info" />
            <StatCard
              label="Last scan"
              value={loading ? "…" : formatWhenShort(lastAccountScan)}
            />
          </div>
        }
      />

      {message ? <p className="text-sm text-emerald-400">{message}</p> : null}
      {!canManage ? (
        <PermissionDeniedNotice
          session={session}
          needed="analyst"
          action="connect a cloud account, run a scan, or delete a connection"
        />
      ) : null}

      <FirstRunJourney
        connectionsCount={connections.length}
        scanCount={counts?.scan_count ?? 0}
        findingsCount={counts?.total ?? 0}
        canManage={canManage}
        session={session}
        onConnect={() => openWizard("aws")}
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

      <ServiceStateBanner
        serviceId="cloud_accounts"
        entry={cloudService}
        registry={counts?.services}
      />

      <CoverageCockpit
        counts={counts}
        scanCount={counts?.scan_count ?? null}
        latestScanLabel={null}
        connections={connections}
      />

      {/* Connected-first: CSS order makes the accounts table the hero once ≥1
          account is connected; the connector picker demotes into a collapsed
          "Add a source" below it. On an empty estate the picker leads. */}
      <div className="flex flex-col gap-6">
      {/* Connect — connector gallery across cloud, code, AI, and data */}
      <div className={hasConnections ? "order-2" : "order-1"}>
        {hasConnections ? (
          <Collapsible
            title="Add a source"
            subtitle="Cloud accounts open a read-only wizard; code, AI, and data sources register in the control plane."
            defaultOpen={false}
            data-testid="add-source-picker"
          >
            {gallery}
          </Collapsible>
        ) : (
          <Section
            label="Connect a source"
            description="Cloud accounts open a read-only wizard; code, AI, and data sources register in the control plane."
          >
            {gallery}
          </Section>
        )}
      </div>

      {/* Connected accounts */}
      <div className={hasConnections ? "order-1" : "order-2"}>
      <Card flush className="overflow-hidden p-5">
        <div className="flex items-start gap-3">
          <span className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2.5">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          </span>
          <div>
            <h2 className="text-base font-semibold text-[var(--foreground)]">
              Connected accounts
            </h2>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              Each row is a tenant-scoped, encrypted connection. Run a scan to see
              live inventory counts and CIS pass rate.
            </p>
          </div>
        </div>

        <div className="mt-5">
          {error ? (
            <ErrorBanner message={error} onRetry={() => void refresh()} />
          ) : loading ? (
            <div className="space-y-2" aria-busy="true">
              {[0, 1, 2].map((i) => (
                <div
                  key={i}
                  className="h-14 animate-pulse rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]"
                />
              ))}
            </div>
          ) : connections.length === 0 ? (
            <PageEmptyState
              icon={Cloud}
              title="No cloud accounts connected"
              detail="Add a read-only AWS, Azure, GCP, or Snowflake account to launch inventory and CIS discovery from the control plane."
              suggestions={[
                "Start with AWS when you want the deepest CSPM and inventory coverage.",
                "Use Snowflake when you want warehouse governance and activity evidence.",
                "Run a local scan if you need repo, image, IaC, or MCP evidence first.",
              ]}
              actions={[
                { label: "Connect cloud", onClick: () => openWizard("aws") },
                { ...RUN_SCAN_ACTION, variant: "secondary" },
              ]}
            />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-[color:var(--border-subtle)]">
              <table className="w-full min-w-[1040px] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] text-[11px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
                    <th className="px-4 py-3 font-medium">Account</th>
                    <th className="px-4 py-3 font-medium">Provider</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Last scan</th>
                    <th className="px-4 py-3 font-medium">Mode</th>
                    <th className="px-4 py-3 font-medium">Schedule</th>
                    <th className="px-4 py-3 text-right font-medium">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map((connection) => {
                    const isBusy = busyId === connection.id;
                    const result = scanResults[connection.id];
                    const scannable = SCANNABLE_PROVIDERS.has(
                      connection.provider,
                    );
                    return (
                      <FragmentRow
                        key={connection.id}
                        connection={connection}
                        isBusy={isBusy}
                        canManage={canManage}
                        scannable={scannable}
                        result={result}
                        onOpenDetail={() => setDetailId(connection.id)}
                        onTest={() => void handleTest(connection)}
                        onScan={() => void handleScan(connection)}
                        onScheduleChange={(value) =>
                          void handleScheduleChange(connection, value)
                        }
                        onDelete={() => void handleDelete(connection)}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>
      </div>
      </div>

      <Collapsible
        title="Roles & permissions"
        subtitle="Viewer reads · Contributor connects and scans · Admin manages keys, policy, and fleet."
        defaultOpen={false}
        data-testid="roles-permissions"
      >
        <RolePermissionsPanel session={session} bare />
      </Collapsible>

      <ConnectionDetailDrawer
        connection={connections.find((c) => c.id === detailId) ?? null}
        result={detailId ? scanResults[detailId] : undefined}
        testResult={detailId ? testResults[detailId] : undefined}
        scanError={detailId ? scanErrors[detailId] : undefined}
        scheduleError={detailId ? scheduleErrors[detailId] : undefined}
        isBusy={busyId === detailId}
        canManage={canManage}
        scannable={
          detailId
            ? SCANNABLE_PROVIDERS.has(
                connections.find((c) => c.id === detailId)?.provider ?? "",
              )
            : false
        }
        onClose={() => setDetailId(null)}
        onTest={(connection) => void handleTest(connection)}
        onScan={(connection) => void handleScan(connection)}
        onDelete={(connection) => {
          setDetailId(null);
          void handleDelete(connection);
        }}
      />

      {wizardOpen ? (
        <AddConnectionWizard
          initialProvider={wizardProvider}
          onClose={() => setWizardOpen(false)}
          onCreated={handleCreated}
        />
      ) : null}

      <CodingAgentDrawer
        open={codingAgentOpen}
        onClose={() => setCodingAgentOpen(false)}
      />
    </div>
  );
}

// ── Connector catalog card ────────────────────────────────────────────────────

// ── Copy + connector cards ────────────────────────────────────────────────────

function CopyTextButton({
  text,
  label = "Copy",
}: {
  text: string;
  label?: string;
}) {
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
      <p className="text-[10px] leading-4 text-[var(--text-tertiary)]">
        {cloudGrantMethodHint(method, provider)}
      </p>
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
  onConnectCodingAgent,
}: {
  activeCategory: ConnectorCategory | "all";
  onCategoryChange: (category: ConnectorCategory | "all") => void;
  search: string;
  onSearchChange: (value: string) => void;
  connectedCountFor: (connector: CatalogConnector) => number;
  canManage: boolean;
  onConnectCloud: (provider: string) => void;
  onConnectCodingAgent: () => void;
}) {
  const query = search.trim().toLowerCase();
  const visible = CONNECTOR_CATALOG.filter((connector) => {
    const inCategory =
      activeCategory === "all" || connector.category === activeCategory;
    if (!inCategory) return false;
    if (!query) return true;
    const haystack =
      `${connector.label} ${connector.tagline} ${connector.keywords ?? ""}`.toLowerCase();
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
                <span className="text-[10px] text-[color:var(--text-tertiary)]">
                  {categoryCount(category.id)}
                </span>
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
  onConnectCodingAgent,
}: {
  connector: CatalogConnector;
  connectedCount: number;
  canManage: boolean;
  onConnectCloud: (provider: string) => void;
  onConnectCodingAgent: () => void;
}) {
  const Icon = connector.icon;
  const categoryLabel =
    CONNECTOR_CATEGORIES.find((c) => c.id === connector.category)?.label ??
    connector.category;
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
            <p className="truncate text-sm font-semibold text-[var(--foreground)]">
              {connector.label}
            </p>
            <p className="truncate text-[11px] text-[var(--text-secondary)]">
              {connector.tagline}
            </p>
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
          <span className="text-[11px] text-[color:var(--text-tertiary)]">
            Not connected
          </span>
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
          <Link
            href={connector.action.href}
            aria-label={`Register ${connector.label}`}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1.5 text-xs font-medium text-[color:var(--foreground)] transition hover:border-emerald-600 hover:text-emerald-700 dark:hover:text-emerald-300"
          >
            Register
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        )}
      </div>
    </Card>
  );
}

// ── Coding-agent onboarding drawer ────────────────────────────────────────────
// Read-only: exposes the local `agent-bom mcp-server` (73 tools) + skills to
// Claude Code / Cursor over MCP. No new capability — discoverability only.

const CODING_AGENT_MCP_SNIPPET = `{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp-server"]
    }
  }
}`;

function CodingAgentDrawer({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
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
          Expose Agent-BOM&apos;s read-only tools — scan, blast-radius,
          exposure-paths, SBOM, compliance, and remediation — to your coding
          agent over the Model Context Protocol. Everything runs locally against
          your control plane; no code or credentials leave your machine.
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
            Add to your agent&apos;s MCP config (Claude Code{" "}
            <code className="font-mono">mcp.json</code>, Cursor{" "}
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
                <strong className="text-[color:var(--foreground)]">Cortex Code</strong>{" "}
                — scan-on-save, exposure-path lookups, and SBOM diffing inside your
                editor.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
              <span>
                <strong className="text-[color:var(--foreground)]">OpenCLAW</strong>{" "}
                — agent-driven remediation and compliance workflows over the same
                read-only tools.
              </span>
            </li>
          </ul>
        </section>

        <p className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-900/50 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-2 text-[11px] text-emerald-700 dark:text-emerald-300">
          <Lock className="h-3.5 w-3.5 shrink-0" /> Read-only. The server never
          writes to your cloud, repos, or control-plane data.
        </p>
      </div>
    </Drawer>
  );
}

// ── Table row + inline scan result ────────────────────────────────────────────

function FragmentRow({
  connection,
  isBusy,
  canManage,
  scannable,
  result,
  onOpenDetail,
  onTest,
  onScan,
  onScheduleChange,
  onDelete,
}: {
  connection: CloudConnectionRecord;
  isBusy: boolean;
  canManage: boolean;
  scannable: boolean;
  result: CloudConnectionScanResponse | undefined;
  onOpenDetail: () => void;
  onTest: () => void;
  onScan: () => void;
  onScheduleChange: (value: string) => void;
  onDelete: () => void;
}) {
  const mode = eventMode(connection);
  return (
      <tr className="group border-b border-[color:var(--border-subtle)] last:border-b-0 align-top">
        <td className="px-4 py-3">
          <button
            type="button"
            onClick={onOpenDetail}
            title="View scan evidence, CIS results, and handoff links"
            className="flex max-w-[240px] items-center gap-1 text-left"
          >
            <span
              className="truncate font-medium text-[var(--foreground)] transition-colors group-hover:text-emerald-400"
              title={connection.display_name}
            >
              {connection.display_name}
            </span>
            <ChevronRight className="h-3.5 w-3.5 shrink-0 text-[var(--text-tertiary)] opacity-0 transition group-hover:opacity-100" />
          </button>
          <p
            className="mt-0.5 max-w-[220px] truncate font-mono text-[11px] text-[var(--text-tertiary)]"
            title={connection.role_ref}
          >
            {connection.role_ref}
          </p>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {connection.has_external_id ? (
              <span className="inline-flex items-center gap-1 rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]">
                <Lock className="h-2.5 w-2.5" /> Secret configured
              </span>
            ) : null}
            {result ? (
              <span className="inline-flex items-center gap-1 rounded border border-emerald-500/30 dark:border-emerald-800/60 bg-emerald-500/10 dark:bg-emerald-950/20 px-1.5 py-0.5 text-[10px] text-emerald-700 dark:text-emerald-300">
                CIS {formatPassRate(result.cis_benchmark.pass_rate)}
              </span>
            ) : null}
            {connection.regions.slice(0, 3).map((region) => (
              <span
                key={region}
                className="rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]"
              >
                {region}
              </span>
            ))}
            {connection.regions.length > 3 ? (
              <span className="text-[10px] text-[var(--text-tertiary)]">
                +{connection.regions.length - 3}
              </span>
            ) : null}
          </div>
        </td>
        <td className="px-4 py-3">
          <span className="inline-flex items-center gap-2 whitespace-nowrap text-[var(--text-secondary)]">
            <ProviderLogo provider={connection.provider} className="h-4 w-4 shrink-0" />
            {providerLabel(connection.provider)}
          </span>
        </td>
        <td className="px-4 py-3">
          <StatusPill status={connection.status} />
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-[var(--text-secondary)]">
          {formatWhen(connection.last_scan_at)}
        </td>
        <td className="px-4 py-3">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[11px] font-medium ${mode.tone}`}
            title={mode.detail}
          >
            <Clock className="h-3 w-3" />
            {mode.label}
          </span>
          <p className="mt-1 max-w-44 truncate text-[10px] text-[var(--text-tertiary)]">
            {mode.detail}
          </p>
        </td>
        <td className="px-4 py-3">
          <label className="sr-only" htmlFor={`schedule-${connection.id}`}>
            Scan schedule
          </label>
          <select
            id={`schedule-${connection.id}`}
            value={connection.scan_interval_minutes?.toString() ?? ""}
            disabled={!canManage}
            onChange={(event) => onScheduleChange(event.target.value)}
            className="w-36 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1.5 text-xs text-[var(--foreground)] outline-none transition focus:border-emerald-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {SCHEDULE_OPTIONS.map(([label, value]) => (
              <option key={label} value={value}>
                {label}
              </option>
            ))}
          </select>
        </td>
        <td className="px-4 py-3">
          <div className="flex justify-end gap-2">
            <button
              onClick={onTest}
              disabled={isBusy || !canManage || !scannable}
              title={
                scannable
                  ? "Verify the stored read-only credential without running inventory"
                  : "Testing for this provider is unavailable"
              }
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 dark:border-emerald-800/70 bg-emerald-500/10 dark:bg-emerald-950/20 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-600 hover:bg-emerald-500/10 dark:hover:bg-emerald-950/40 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              {isBusy ? "Working…" : "Test"}
            </button>
            <button
              onClick={onScan}
              disabled={isBusy || !canManage || !scannable}
              title={
                scannable
                  ? "Run a read-only inventory and CIS scan"
                  : "Scanning for this provider is unavailable"
              }
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              {isBusy ? "Working…" : "Run scan"}
            </button>
            <button
              onClick={onDelete}
              disabled={isBusy || !canManage}
              aria-label={`Delete ${connection.display_name}`}
              className="inline-flex items-center gap-1 rounded-lg border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-300 transition hover:bg-red-500/10 dark:hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete
            </button>
          </div>
        </td>
      </tr>
  );
}

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
  const statusDetail =
    connection.status === "error" ? connection.status_detail : "";

  return (
    <Drawer
      open={Boolean(connection)}
      onClose={onClose}
      size="xl"
      eyebrow={providerLabel(connection.provider)}
      title={connection.display_name}
      subtitle={
        <span className="font-mono text-[11px] text-[color:var(--text-tertiary)]">
          {connection.role_ref}
        </span>
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
            Read-only credential verified. No inventory, CIS, findings, or
            resource writes ran.
          </div>
        ) : null}
        {!result && handoffScanId ? (
          <ScanHandoffLinks scanId={handoffScanId} />
        ) : null}
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
            No scan has run for this account yet. Use “Run scan” below to
            populate inventory, CIS results, and evidence links.
          </p>
        ) : null}
      </div>
    </Drawer>
  );
}

function ScanResultPanel({ result }: { result: CloudConnectionScanResponse }) {
  const { inventory, cis_benchmark: cis } = result;
  // Snowflake reports a discovered-agent count; AWS/Azure/GCP report estate
  // resource + identity counts. Render whichever the provider returned.
  const isSnowflake = inventory.agent_count != null;
  const warnings = inventory.warnings ?? [];
  return (
    <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="inline-flex items-center gap-2 text-xs font-semibold text-[var(--foreground)]">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          Read-only scan complete
        </p>
        <span className="font-mono text-[10px] text-[var(--text-tertiary)]">
          scan {result.scan_id.slice(0, 8)}
        </span>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {isSnowflake ? (
          <StatTile
            icon={Boxes}
            label="Agents"
            value={String(inventory.agent_count ?? 0)}
          />
        ) : (
          <>
            <StatTile
              icon={Boxes}
              label="Resources"
              value={String(inventory.resource_count ?? 0)}
            />
            <StatTile
              icon={Fingerprint}
              label="Identities"
              value={String(inventory.identity_count ?? 0)}
            />
          </>
        )}
        <StatTile
          icon={CheckCircle2}
          label="CIS passed"
          value={cis.passed == null ? "—" : `${cis.passed}/${cis.total ?? "—"}`}
        />
        <StatTile
          icon={KeyRound}
          label="CIS pass rate"
          value={formatPassRate(cis.pass_rate)}
        />
      </div>
      {warnings.length > 0 ? (
        <p className="mt-3 text-[11px] leading-5 text-amber-300">
          {warnings.join(" · ")}
        </p>
      ) : null}
      <p className="mt-3 text-[11px] leading-5 text-[var(--text-tertiary)]">
        {result.audit_metadata.note}
      </p>
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
        <span className="font-mono text-[10px] text-[var(--text-tertiary)]">
          scan {scanId.slice(0, 8)}
        </span>
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
      <p className="mt-1.5 text-lg font-semibold text-[var(--foreground)]">
        {value}
      </p>
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
  /** Non-secret provider params keyed by field key (tenant_id, project_id, user, …). */
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
    buildWizardForm(
      initialProvider && providerOption(initialProvider)
        ? initialProvider
        : "aws",
    ),
  );
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [generatedExternalId, setGeneratedExternalId] = useState("");
  const [grantMethod, setGrantMethod] = useState<CloudGrantMethod>("cli");

  const provider = useMemo(
    () => providerOption(form.provider) ?? PROVIDER_OPTIONS[0]!,
    [form.provider],
  );

  // AWS is the only provider whose "secret" is an ExternalId that agent-bom
  // mints (the customer bakes it into their role's trust policy). It must be
  // generated exactly once and carried unchanged through Setup → Details so the
  // value shown in the grant script the user copies is the value the connection
  // stores. The other providers' secretField is a real credential the user
  // pastes, so no generation happens there.
  const isAws = provider.value === "aws";

  // Generate the single AWS ExternalId once, the first time AWS is active.
  useEffect(() => {
    if (!isAws) return;
    setGeneratedExternalId((current) => current || generateConnectionExternalId());
  }, [isAws]);

  // Keep the submitted external_id in lockstep with the carried ExternalId so
  // Setup, Details, and the created connection can never diverge.
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
    setForm((current) => ({
      ...current,
      auth: { ...current.auth, [key]: value },
    }));
  }

  function selectProvider(value: string) {
    setForm((current) => {
      // Re-selecting the already-active provider must not wipe entered fields.
      if (current.provider === value) return current;
      // Drop any carried ExternalId; the effect re-mints one iff the new
      // provider is AWS. Reset provider-specific fields so a previous
      // provider's params don't leak.
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

  // Explicit, deliberate re-mint. Updates the carried id and the submitted
  // external_id together so they stay identical; the operator must re-copy the
  // grant script and re-apply the trust policy after regenerating.
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
      // Drop the plaintext secret from component state immediately on success.
      setForm((current) => ({ ...current, external_id: "" }));
      onCreated(created);
    } catch (err) {
      setFormError(
        err instanceof Error ? err.message : "Failed to create connection.",
      );
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
              <h2 className="text-base font-semibold text-[var(--foreground)]">
                Add cloud account
              </h2>
              <p className="text-xs text-[var(--text-secondary)]">
                Read-only connection · step {step + 1} of 3
              </p>
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
                          <ProviderLogo
                            provider={option.value}
                            className="h-5 w-5"
                          />
                        </span>
                        <span className="min-w-0">
                          <span className="block text-sm font-medium text-[var(--foreground)]">
                            {option.label}
                          </span>
                          <span className="mt-0.5 block text-[11px] text-[var(--text-secondary)]">
                            {option.tagline}
                          </span>
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
                    Run this in your {provider.label} to create the read-only
                    grant, then paste the {provider.roleField.label.toLowerCase()}{" "}
                    in the next step.
                  </p>
                  <div className="mt-4 space-y-2">
                    <GrantMethodPicker
                      method={grantMethod}
                      onChange={setGrantMethod}
                      provider={provider.value}
                    />
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--text-tertiary)]">
                        {cloudGrantMethodLabel(grantMethod)} grant script
                      </p>
                      {deployScript ? (
                        <CopyTextButton text={deployScript} label="Copy script" />
                      ) : null}
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
                          <p
                            data-testid="wizard-external-id"
                            className="break-all font-mono text-[11px] text-[var(--foreground)]"
                          >
                            {generatedExternalId}
                          </p>
                        ) : null}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {generatedExternalId ? (
                          <CopyTextButton text={generatedExternalId} label="Copy" />
                        ) : null}
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
                          The ExternalId is embedded in the grant script and is
                          what the connection stores — it carries to the next step
                          unchanged. Regenerate only before you apply the grant.
                        </li>
                      ) : null}
                      <li className="flex items-start gap-1.5">
                        <Lock className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                        The {provider.secretField.label.toLowerCase()} is stored
                        encrypted at rest and never displayed again.
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
                    onChange={(event) =>
                      update("display_name", event.target.value)
                    }
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
                      onChange={(event) =>
                        updateAuth(field.key, event.target.value)
                      }
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
                    // AWS: the single generated ExternalId, read-only, identical
                    // to the value in the Setup grant script. Never a fresh mint
                    // here — that would not match the applied trust policy.
                    <div className="flex items-center justify-between gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2">
                      <code
                        data-testid="wizard-external-id-details"
                        className="min-w-0 break-all font-mono text-sm text-[var(--foreground)]"
                      >
                        {form.external_id}
                      </code>
                      <CopyTextButton text={form.external_id} label="Copy" />
                    </div>
                  ) : provider.secretField.multiline ? (
                    <textarea
                      autoComplete="off"
                      rows={5}
                      value={form.external_id}
                      onChange={(event) =>
                        update("external_id", event.target.value)
                      }
                      placeholder={provider.secretField.placeholder}
                      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-xs text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                    />
                  ) : (
                    <input
                      type="password"
                      autoComplete="off"
                      value={form.external_id}
                      onChange={(event) =>
                        update("external_id", event.target.value)
                      }
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
                      onChange={(event) =>
                        update("regions", event.target.value)
                      }
                      placeholder="us-east-1, us-west-2"
                      className="w-full rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-3 py-2 font-mono text-sm text-[var(--foreground)] outline-none transition focus:border-emerald-500"
                    />
                  </label>
                ) : null}
              </div>
            ) : null}

            {formError ? (
              <p className="text-sm text-red-400">{formError}</p>
            ) : null}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-[color:var(--border-subtle)] px-5 py-4">
            <button
              type="button"
              onClick={() =>
                step === 0 ? onClose() : setStep((s) => (s - 1) as 0 | 1 | 2)
              }
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
          <span
            className={`text-xs ${index <= step ? "text-[var(--foreground)]" : "text-[var(--text-tertiary)]"}`}
          >
            {label}
          </span>
          {index < labels.length - 1 ? (
            <span className="h-px flex-1 bg-[color:var(--border-subtle)]" />
          ) : null}
        </div>
      ))}
    </div>
  );
}
