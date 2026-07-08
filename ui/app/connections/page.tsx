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
  Boxes,
  Fingerprint,
  KeyRound,
  FileSearch,
  GitGraph,
  ListChecks,
  ClipboardList,
  Eye,
  EyeOff,
  Server,
  ShieldAlert,
  ScrollText,
  Building2,
  Plug,
  Terminal,
  MapPin,
} from "lucide-react";

import {
  api,
  type CloudConnectionRecord,
  type CloudConnectionCreateRequest,
  type CloudConnectionTestResponse,
  type CloudConnectionScanResponse,
} from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { ErrorBanner } from "@/components/empty-state";
import { PageEmptyState } from "@/components/states/page-state";
import { Card, Section } from "@/components/card";
import { Collapsible } from "@/components/collapsible";
import { StatCard } from "@/components/stat-card";
import { RUN_SCAN_ACTION } from "@/lib/empty-state-actions";
import { vendorLogo } from "@/lib/vendor-logos";

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

function eventMode(connection: CloudConnectionRecord): {
  label: string;
  detail: string;
  tone: string;
} {
  if (connection.last_event_at) {
    return {
      label: "Event-driven",
      detail: `Last event ${formatWhen(connection.last_event_at)}`,
      tone: "border-cyan-900/60 bg-cyan-950/30 text-cyan-200",
    };
  }
  if (connection.scan_interval_minutes) {
    return {
      label: "Scheduled scan",
      detail: `Every ${connection.scan_interval_minutes} min`,
      tone: "border-amber-900/60 bg-amber-950/30 text-amber-200",
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
      return "border-emerald-900/60 bg-emerald-950/30 text-emerald-300";
    case "error":
      return "border-red-900/60 bg-red-950/30 text-red-300";
    default:
      return "border-amber-900/60 bg-amber-950/30 text-amber-300";
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
    <img src={src} alt={`${providerLabel(provider)} logo`} className={className} />
  );
}

function ReadinessBadge({ readiness }: { readiness: ProviderReadiness }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-900/60 bg-emerald-950/30 px-2.5 py-0.5 text-[11px] font-medium text-emerald-300">
      <CheckCircle2 className="h-3 w-3" />
      {readiness === "live" ? "Live" : "Live"}
    </span>
  );
}

// ── Capability / security posture (each backed by a real model fact) ───────────

const SECURITY_FACTS: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  detail: string;
}[] = [
  {
    icon: Eye,
    title: "Read-only",
    detail:
      "The broker assumes a read-only role/identity (SecurityAudit · Reader · roles/viewer) and runs inventory + CIS with no mutating API calls.",
  },
  {
    icon: EyeOff,
    title: "No secret values",
    detail:
      "The one secret per connection is Fernet-encrypted at rest and never returned — responses expose only has_external_id.",
  },
  {
    icon: Server,
    title: "Your control plane",
    detail:
      "Scans run from your self-hosted control plane against a short-lived brokered credential; no long-lived customer key is retained.",
  },
  {
    icon: ShieldAlert,
    title: "Fail-closed",
    detail:
      "Create refuses with 503 when AGENT_BOM_CONNECTIONS_KEY is unset rather than storing a plaintext secret.",
  },
  {
    icon: ScrollText,
    title: "Signed audit",
    detail:
      "Every create / scan / delete writes a tamper-evident entry to the hash-chained audit log.",
  },
  {
    icon: Building2,
    title: "Tenant isolation",
    detail:
      "Each endpoint enforces tenant scoping + the scan RBAC permission (OIDC/SAML/SCIM-backed roles); reads and deletes never cross tenants.",
  },
];

export default function ConnectionsPage() {
  const { hasCapability, session } = useAuthState();
  const canManage = !session?.auth_required || hasCapability("scan.run");

  const [connections, setConnections] = useState<CloudConnectionRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardProvider, setWizardProvider] = useState<string | undefined>(
    undefined,
  );
  const [busyId, setBusyId] = useState<string | null>(null);
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

  const connectedByProvider = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const connection of connections) {
      counts[connection.provider] = (counts[connection.provider] ?? 0) + 1;
    }
    return counts;
  }, [connections]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <section className="rounded-3xl border border-[color:var(--border-subtle)] bg-[linear-gradient(135deg,var(--surface),var(--surface-elevated))] p-6 shadow-2xl shadow-black/10">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-[0.22em] text-emerald-400">
              Connect &amp; deploy
            </p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[var(--foreground)]">
              Connectors
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-[var(--text-secondary)]">
              Connect a customer cloud account (AWS, Azure, GCP, or Snowflake)
              in read-only mode, then launch inventory and CIS discovery against
              a short-lived brokered credential. The connection secret is
              encrypted at rest and is never returned to the browser.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => void refresh()}
              className="inline-flex items-center gap-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-4 py-2 text-sm text-[var(--foreground)] transition hover:border-[color:var(--border-strong)]"
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
          </div>
        </div>

        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Connections"
            value={loading ? "…" : connections.length}
          />
          <StatCard
            label="Active"
            value={loading ? "…" : activeCount}
            accent="info"
          />
          <StatCard label="Providers" value="4" />
          <StatCard label="Secret storage" value="Encrypted" />
        </div>

        {message ? (
          <p className="mt-4 text-sm text-emerald-400">{message}</p>
        ) : null}
        {!canManage ? (
          <p className="mt-3 text-sm text-amber-300">
            Your role can review connections but cannot create, scan, or delete
            them.
          </p>
        ) : null}
      </section>

      {/* Connect & deploy — provider connector catalog */}
      <Section
        label="Connect a provider"
        description="Pick a read-only connector. Each one assumes a read-only role/identity and runs the same inventory + CIS discovery the platform uses elsewhere."
      >
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {PROVIDER_OPTIONS.map((option) => (
            <ConnectorCard
              key={option.value}
              option={option}
              connectedCount={connectedByProvider[option.value] ?? 0}
              canManage={canManage}
              onConnect={() => openWizard(option.value)}
            />
          ))}
        </div>
      </Section>

      {/* Security posture */}
      <Section
        label="Security posture"
        description="What every connection guarantees — each card is enforced by the connection store, broker, and API gate, not marketing copy."
      >
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {SECURITY_FACTS.map(({ icon: Icon, title, detail }) => (
            <Card key={title} className="flex gap-3">
              <span className="h-fit rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-2">
                <Icon className="h-4 w-4 text-emerald-400" />
              </span>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-[var(--foreground)]">
                  {title}
                </p>
                <p className="mt-1 text-xs leading-5 text-[var(--text-secondary)]">
                  {detail}
                </p>
              </div>
            </Card>
          ))}
        </div>
      </Section>

      {/* Connected accounts */}
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
              Each row is a tenant-scoped, encrypted connection. Run a read-only
              scan to see live inventory counts and CIS pass rate.
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
              <table className="w-full min-w-[880px] border-collapse text-left text-sm">
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
                    const scanError = scanErrors[connection.id];
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
                        testResult={testResults[connection.id]}
                        scanError={scanError}
                        scheduleError={scheduleErrors[connection.id]}
                        statusDetail={
                          connection.status === "error"
                            ? connection.status_detail
                            : ""
                        }
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

      {wizardOpen ? (
        <AddConnectionWizard
          initialProvider={wizardProvider}
          onClose={() => setWizardOpen(false)}
          onCreated={handleCreated}
        />
      ) : null}
    </div>
  );
}

// ── Connector catalog card ────────────────────────────────────────────────────

function ConnectorCard({
  option,
  connectedCount,
  canManage,
  onConnect,
}: {
  option: ProviderOption;
  connectedCount: number;
  canManage: boolean;
  onConnect: () => void;
}) {
  const authSummary = [
    option.roleField.label,
    ...option.authFields.map((field) => field.label),
    option.secretField.label,
  ].join(" · ");
  return (
    <Card className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)]">
            <ProviderLogo provider={option.value} className="h-6 w-6" />
          </span>
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-[var(--foreground)]">
              {option.label}
            </p>
            <p className="truncate text-[11px] text-[var(--text-secondary)]">
              {option.tagline}
            </p>
          </div>
        </div>
        <ReadinessBadge readiness={option.readiness} />
      </div>

      <dl className="space-y-2 text-[11px]">
        <CardFact icon={KeyRound} term="Permissions" detail={option.permissions} />
        <CardFact icon={Fingerprint} term="Auth" detail={authSummary} />
        <CardFact
          icon={MapPin}
          term="Regions"
          detail={option.usesRegions ? "Per-region (you choose)" : "Account-wide"}
        />
      </dl>

      {connectedCount > 0 ? (
        <p className="inline-flex items-center gap-1.5 text-[11px] text-emerald-300">
          <CheckCircle2 className="h-3 w-3" />
          {connectedCount} connected
        </p>
      ) : null}

      <Collapsible
        title="Setup steps & CLI"
        icon={Terminal}
        defaultOpen={false}
        className="bg-[color:var(--surface-elevated)]/40"
      >
        <ol className="list-decimal space-y-1.5 pl-4 text-[11px] leading-5 text-[var(--text-secondary)]">
          {option.setupSteps.map((stepText) => (
            <li key={stepText}>{stepText}</li>
          ))}
        </ol>
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1.5">
          <Terminal className="h-3 w-3 shrink-0 text-[var(--text-tertiary)]" />
          <code className="overflow-x-auto whitespace-nowrap font-mono text-[11px] text-[var(--foreground)]">
            {option.cli}
          </code>
        </div>
      </Collapsible>

      <button
        type="button"
        onClick={onConnect}
        disabled={!canManage}
        aria-label={`Connect ${option.value}`}
        className="mt-auto inline-flex items-center justify-center gap-1.5 rounded-xl border border-emerald-700/60 bg-emerald-500/10 px-3 py-2 text-sm font-medium text-emerald-200 transition hover:border-emerald-500 hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Plug className="h-4 w-4" />
        Connect
      </button>
    </Card>
  );
}

function CardFact({
  icon: Icon,
  term,
  detail,
}: {
  icon: React.ComponentType<{ className?: string }>;
  term: string;
  detail: string;
}) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-3 w-3 shrink-0 text-[var(--text-tertiary)]" />
      <div className="min-w-0">
        <dt className="inline text-[var(--text-tertiary)]">{term}: </dt>
        <dd className="inline text-[var(--text-secondary)]">{detail}</dd>
      </div>
    </div>
  );
}

// ── Table row + inline scan result ────────────────────────────────────────────

function FragmentRow({
  connection,
  isBusy,
  canManage,
  scannable,
  result,
  testResult,
  scanError,
  scheduleError,
  statusDetail,
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
  testResult: CloudConnectionTestResponse | undefined;
  scanError: string | undefined;
  scheduleError: string | undefined;
  statusDetail: string;
  onTest: () => void;
  onScan: () => void;
  onScheduleChange: (value: string) => void;
  onDelete: () => void;
}) {
  const handoffScanId = result?.scan_id ?? connection.last_scan_id;
  const mode = eventMode(connection);
  const showDetail = Boolean(
    result ||
      testResult ||
      handoffScanId ||
      scanError ||
      scheduleError ||
      statusDetail,
  );
  return (
    <>
      <tr className="border-b border-[color:var(--border-subtle)] last:border-b-0 align-top">
        <td className="px-4 py-3">
          <p className="font-medium text-[var(--foreground)]">
            {connection.display_name}
          </p>
          <p className="mt-0.5 break-all font-mono text-[11px] text-[var(--text-tertiary)]">
            {connection.role_ref}
          </p>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            {connection.has_external_id ? (
              <span className="inline-flex items-center gap-1 rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]">
                <Lock className="h-2.5 w-2.5" /> Secret configured
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
          <span className="inline-flex items-center gap-2 text-[var(--text-secondary)]">
            <ProviderLogo provider={connection.provider} className="h-4 w-4" />
            {providerLabel(connection.provider)}
          </span>
        </td>
        <td className="px-4 py-3">
          <StatusPill status={connection.status} />
        </td>
        <td className="px-4 py-3 text-[var(--text-secondary)]">
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
              className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-800/70 bg-emerald-950/20 px-3 py-1.5 text-xs font-medium text-emerald-200 transition hover:border-emerald-600 hover:bg-emerald-950/40 disabled:cursor-not-allowed disabled:opacity-60"
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
              className="inline-flex items-center gap-1 rounded-lg border border-red-900/60 bg-red-950/20 px-3 py-1.5 text-xs font-medium text-red-300 transition hover:bg-red-950/40 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Delete
            </button>
          </div>
        </td>
      </tr>
      {showDetail ? (
        <tr className="border-b border-[color:var(--border-subtle)] last:border-b-0 bg-[color:var(--surface-elevated)]/40">
          <td colSpan={7} className="px-4 pb-4 pt-0">
            {result ? <ScanResultPanel result={result} /> : null}
            {!result && testResult ? (
              <div className="rounded-xl border border-emerald-900/60 bg-emerald-950/20 p-3 text-xs text-emerald-200">
                Read-only credential verified. No inventory, CIS, findings, or
                resource writes ran.
              </div>
            ) : null}
            {!result && handoffScanId ? (
              <ScanHandoffLinks scanId={handoffScanId} />
            ) : null}
            {!result && scanError ? (
              <div className="rounded-xl border border-red-900/60 bg-red-950/20 p-3 text-xs text-red-300">
                {scanError}
              </div>
            ) : null}
            {!result && !scanError && scheduleError ? (
              <div className="rounded-xl border border-red-900/60 bg-red-950/20 p-3 text-xs text-red-300">
                {scheduleError}
              </div>
            ) : null}
            {!result && !scanError && !scheduleError && statusDetail ? (
              <div className="rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 text-xs text-amber-200">
                {statusDetail}
              </div>
            ) : null}
          </td>
        </tr>
      ) : null}
    </>
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
      className="inline-flex items-center gap-1.5 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] px-2.5 py-1.5 text-[11px] font-medium text-[var(--foreground)] transition hover:border-emerald-700 hover:text-emerald-300"
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

  const provider = useMemo(
    () => providerOption(form.provider) ?? PROVIDER_OPTIONS[0]!,
    [form.provider],
  );

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
      // Reset provider-specific fields so a previous provider's params don't leak.
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
                  Read-only setup
                </p>
                <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-4 text-xs leading-6 text-[var(--text-secondary)]">
                  <p className="text-[var(--foreground)]">
                    Set up a read-only {provider.label} connection:
                  </p>
                  <ol className="mt-2 list-decimal space-y-1.5 pl-4">
                    {provider.setupSteps.map((stepText) => (
                      <li key={stepText}>{stepText}</li>
                    ))}
                  </ol>
                  <div className="mt-3 flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2.5 py-1.5">
                    <Terminal className="h-3 w-3 shrink-0 text-[var(--text-tertiary)]" />
                    <code className="overflow-x-auto whitespace-nowrap font-mono text-[11px] text-[var(--foreground)]">
                      {provider.cli}
                    </code>
                  </div>
                  <p className="mt-3 inline-flex items-center gap-1.5 text-emerald-300">
                    <Lock className="h-3.5 w-3.5" /> The{" "}
                    {provider.secretField.label.toLowerCase()} is stored
                    encrypted and never displayed again.
                  </p>
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
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
                    {provider.secretField.label}
                  </span>
                  {provider.secretField.multiline ? (
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
                    <Lock className="h-3 w-3" /> {provider.secretField.hint}
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
                onClick={() => setStep((s) => (s + 1) as 0 | 1 | 2)}
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
