"use client";

import { PageLoadingState } from "@/components/states/page-loading-state";

import { TextField } from "@/components/text-field";

import { Collapsible } from "@/components/collapsible";
import { CATEGORY_CHIP_TONE,eventMode,formatWhen,isContinuousMode,isOrganizationScope,kindOption,OPERATING_SURFACES,providerLabel,SCANNABLE_PROVIDERS,SCHEDULE_OPTIONS,SOURCE_KIND_OPTIONS,sourceTargetSpec,type FormState } from "@/components/connections/catalog";
import { ModeChip,ProviderLogo,SourceStatusPill,StatusPill,summarizeProviders } from "@/components/connections/display";
import { ProviderContractCard } from "@/components/connections/provider-contract";
import { DemoConnectCard } from "@/components/demo-mode-cta";
import { ErrorBanner } from "@/components/empty-state";
import { ServiceStateBanner,ServiceStateChip } from "@/components/service-state-chip";
import { StatStrip } from "@/components/stat-strip";
import { PageEmptyState } from "@/components/states/page-state";
import {
  type CloudConnectionRecord,
  type ConnectorHealthResponse,
  type DiscoveryProvidersResponse,
  type SourceKind
} from "@/lib/api";
import {
  SOURCE_CATEGORY_OPTIONS,
  type SourceCategory,
  type UnifiedSourceRow
} from "@/lib/connections-sources";
import { serviceEntry } from "@/lib/service-registry";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Clock,
  Plus,
  Search,
  ServerCog,
  ShieldCheck,
  Trash2
} from "lucide-react";
import Link from "next/link";


// ── Sources segment (unified table + management) ──────────────────────────────

export interface SourcesSegmentProps {
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
  canUpdateConnections: boolean;
  canDeleteConnections: boolean;
  onCloudTest: (connection: CloudConnectionRecord) => void;
  onCloudScan: (connection: CloudConnectionRecord) => void;
  onCloudDelete: (connection: CloudConnectionRecord) => void;
  onCloudScheduleChange: (connection: CloudConnectionRecord, value: string) => void;
  onCloudScanModeChange: (connection: CloudConnectionRecord, continuous: boolean) => void;
  isDemoMode: boolean;
  dataSourcesService: ReturnType<typeof serviceEntry>;
  servicesRegistry: Parameters<typeof serviceEntry>[0];
  formMessage: string | null;
  fleetSyncSummary: string | null;
  syncingFleet: boolean;
  canManageFleet: boolean;
  onFleetSync: () => void;
  connectorHealth: ConnectorHealthResponse[];
  connectorHealthUnavailable: boolean;
  connectorNames: string[];
  healthyConnectors: number;
  providerContracts: DiscoveryProvidersResponse | null;
  providerSummary: ReturnType<typeof summarizeProviders>;
  schedulesCount: number;
  schedulesUnavailable: boolean;
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


export function SourcesSegment(props: SourcesSegmentProps) {
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
    canUpdateConnections,
    canDeleteConnections,
    onCloudTest,
    onCloudScan,
    onCloudDelete,
    onCloudScheduleChange,
    onCloudScanModeChange,
    isDemoMode,
    dataSourcesService,
    servicesRegistry,
    formMessage,
    fleetSyncSummary,
    syncingFleet,
    canManageFleet,
    onFleetSync,
    connectorHealth,
    connectorHealthUnavailable,
    connectorNames,
    healthyConnectors,
    providerContracts,
    providerSummary,
    schedulesCount,
    schedulesUnavailable,
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
  const targetSpec = sourceTargetSpec(formState.kind);

  return (
    <div className="space-y-5">
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
        <PageLoadingState compact title="Loading sources" detail="Reading saved connections and sources" />
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
        <p className="rounded-xl border border-outline bg-surface-muted px-4 py-10 text-center text-sm text-ink-secondary">
          No sources match the current filters.
        </p>
      ) : (
        <div className="relative overflow-x-auto rounded-xl border border-outline" data-testid="unified-sources-table">
          <table className="w-full min-w-[1000px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-outline bg-surface-elevated text-[11px] uppercase tracking-[0.16em] text-ink-tertiary">
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
                  canUpdate={canUpdateConnections}
                  canDelete={canDeleteConnections}
                  onOpen={() => onRowOpen(row)}
                  onCloudTest={onCloudTest}
                  onCloudScan={onCloudScan}
                  onCloudDelete={onCloudDelete}
                  onCloudScheduleChange={onCloudScheduleChange}
                  onCloudScanModeChange={onCloudScanModeChange}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

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
            className="inline-flex items-center gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-outline-strong disabled:cursor-not-allowed disabled:opacity-60"
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
            value: loading ? "…" : connectorHealthUnavailable ? "Unavailable" : `${healthyConnectors}/${connectorHealth.length || 0}`,
            accent:
              connectorHealth.length > 0 && healthyConnectors === connectorHealth.length
                ? "success"
                : "neutral",
          },
          {
            label: "Schedules",
            value: loading ? "…" : schedulesUnavailable ? "Unavailable" : schedulesCount,
            hint: schedulesUnavailable ? "Read not available" : nextSchedule ? `Next ${formatWhen(nextSchedule)}` : "None yet",
          },
          {
            label: "Providers",
            value: loading ? "…" : providerContracts ? providerSummary.total : "Unavailable",
            hint: providerContracts ? `${providerSummary.readOnly} read-only` : "Read not available",
          },
        ]}
      />

      {!isDemoMode ? (
        <div className="grid gap-4 xl:grid-cols-2">
          <Collapsible key={createKey} title="Register a source" icon={Plus} defaultOpen={createDefaultOpen}>
            <form className="space-y-4" onSubmit={onCreateSource}>
              <TextField label="Display name"
                  value={formState.display_name}
                  onChange={(event) => onUpdateForm("display_name", event.target.value)}
                  placeholder="Payments monorepo" />

              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                    Kind
                  </span>
                  <select
                    value={formState.kind}
                    onChange={(event) => onUpdateForm("kind", event.target.value as SourceKind)}
                    className="w-full rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-[color:var(--accent-border)]"
                  >
                    {SOURCE_KIND_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>

                <TextField label="Owner"
                    value={formState.owner}
                    onChange={(event) => onUpdateForm("owner", event.target.value)}
                    placeholder="platform-security" />
              </div>

              {selectedKind.mode === "Read-only connector" ? (
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                    Connector name
                  </span>
                  <select
                    value={formState.connector_name}
                    onChange={(event) => onUpdateForm("connector_name", event.target.value)}
                    className="w-full rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-[color:var(--accent-border)]"
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

              {targetSpec ? (
                <label className="block">
                  <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                    {targetSpec.label}
                  </span>
                  <input
                    value={formState.target}
                    onChange={(event) => onUpdateForm("target", event.target.value)}
                    aria-label={targetSpec.label}
                    className="w-full rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-[color:var(--accent-border)]"
                    placeholder={targetSpec.placeholder}
                    autoComplete="off"
                  />
                  <span className="mt-1.5 block text-xs leading-5 text-ink-secondary">
                    {targetSpec.help}
                  </span>
                </label>
              ) : null}

              <label className="block">
                <span className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                  Description
                </span>
                <textarea
                  value={formState.description}
                  onChange={(event) => onUpdateForm("description", event.target.value)}
                  rows={2}
                  className="w-full rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-[color:var(--accent-border)]"
                  placeholder={selectedKind.detail}
                />
              </label>

              <div className="rounded-lg border border-outline bg-surface-elevated p-3 text-xs leading-5 text-ink-secondary">
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
              <p className="text-sm text-ink-secondary">No connector health state loaded yet.</p>
            ) : (
              <div className="space-y-2">
                {connectorHealth.map((connector) => (
                  <div
                    key={connector.connector}
                    className="rounded-lg border border-outline bg-surface-elevated p-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-foreground">{connector.connector}</h3>
                        <p className="mt-1 text-xs leading-5 text-ink-secondary">{connector.message}</p>
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
          <p className="text-sm text-ink-secondary">
            Backend provider registry: scan modes, declared permissions, and read-only guarantees.
          </p>
          <StatStrip
            items={[
              { label: "Providers", value: loading ? "…" : providerContracts ? providerSummary.total : "Unavailable" },
              { label: "Read-only", value: loading ? "…" : providerContracts ? `${providerSummary.readOnly}/${providerSummary.total}` : "Unavailable" },
              { label: "Scope-zero modes", value: loading ? "…" : providerContracts ? providerSummary.scopeZero : "Unavailable" },
              { label: "Declared permissions", value: loading ? "…" : providerContracts ? providerSummary.permissionCount : "Unavailable" },
            ]}
          />
          {providerContracts?.warnings?.length ? (
            <div className="rounded-lg border border-[color:var(--status-warn-border)] bg-[color:var(--status-warn-bg)] p-3 text-xs leading-5 text-ink-secondary">
              {providerContracts.warnings.slice(0, 2).join(" · ")}
            </div>
          ) : null}
          <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
            {!providerContracts && !loading ? (
              <div className="rounded-lg border border-dashed border-outline bg-surface-elevated p-4 text-sm text-ink-secondary">
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
                  <div className="rounded-lg border border-outline bg-surface-elevated p-4 transition-colors hover:border-outline-strong">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span className="rounded-lg border border-outline bg-surface p-2">
                          <Icon className="h-4 w-4 text-[color:var(--accent)]" />
                        </span>
                        <div>
                          <p className="text-sm font-semibold text-foreground">{surface.title}</p>
                          <p className="mt-1 text-xs leading-5 text-ink-secondary">{surface.summary}</p>
                        </div>
                      </div>
                      <ArrowRight className="mt-1 h-4 w-4 text-ink-tertiary" />
                    </div>
                    <div className="mt-4 text-[11px] uppercase tracking-[0.18em] text-ink-tertiary">
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


export function SourceFilterToolbar({
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
                  ? "border-emerald-600/60 bg-emerald-500/10 text-foreground"
                  : "border-outline text-ink-secondary hover:border-outline-strong"
              }`}
            >
              {category.label}
              <span className="text-[10px] text-ink-tertiary">
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
          className="rounded-lg border border-outline bg-surface-muted px-3 py-1.5 text-sm text-foreground outline-none transition focus:border-emerald-500"
        >
          <option value="all">All statuses</option>
          {statusChoices.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
        <label className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-tertiary" />
          <input
            type="search"
            aria-label="Search sources"
            placeholder="Search sources…"
            value={filterQuery}
            onChange={(event) => onFilterQuery(event.target.value)}
            className="w-full rounded-lg border border-outline bg-surface-muted py-1.5 pl-8 pr-3 text-sm text-foreground outline-none transition focus:border-emerald-500"
          />
        </label>
      </div>
    </div>
  );
}


export function CategoryChip({ category }: { category: SourceCategory }) {
  const label = SOURCE_CATEGORY_OPTIONS.find((c) => c.id === category)?.label ?? category;
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${CATEGORY_CHIP_TONE[category]}`}>
      {label}
    </span>
  );
}


export function UnifiedRow({
  row,
  connection,
  busyId,
  canManage,
  canUpdate,
  canDelete,
  onOpen,
  onCloudTest,
  onCloudScan,
  onCloudDelete,
  onCloudScheduleChange,
  onCloudScanModeChange,
}: {
  row: UnifiedSourceRow;
  connection: CloudConnectionRecord | null;
  busyId: string | null;
  canManage: boolean;
  canUpdate: boolean;
  canDelete: boolean;
  onOpen: () => void;
  onCloudTest: (connection: CloudConnectionRecord) => void;
  onCloudScan: (connection: CloudConnectionRecord) => void;
  onCloudDelete: (connection: CloudConnectionRecord) => void;
  onCloudScheduleChange: (connection: CloudConnectionRecord, value: string) => void;
  onCloudScanModeChange: (connection: CloudConnectionRecord, continuous: boolean) => void;
}) {
  const isCloud = row.origin === "cloud" && connection != null;
  const isBusy = isCloud ? busyId === connection!.id : false;
  const scannable = isCloud ? SCANNABLE_PROVIDERS.has(connection!.provider) : false;
  const mode = isCloud ? eventMode(connection!) : null;
  const continuous = isCloud && isContinuousMode(connection!);

  return (
    <tr className="group border-b border-outline last:border-b-0 align-top">
      <td className="px-4 py-3">
        <button
          type="button"
          onClick={onOpen}
          title="View scan handoff, evidence, schedule, and actions"
          className="flex max-w-[260px] items-center gap-1 text-left"
        >
          <span
            className="truncate font-medium text-foreground transition-colors group-hover:text-emerald-400"
            title={row.name}
          >
            {row.name}
          </span>
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-ink-tertiary opacity-0 transition group-hover:opacity-100" />
        </button>
        <p className="mt-0.5 max-w-[240px] truncate font-mono text-[11px] text-ink-tertiary" title={row.detail}>
          {row.detail}
        </p>
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-col gap-1.5">
          <span className="inline-flex items-center gap-2 whitespace-nowrap text-ink-secondary">
            {isCloud ? (
              <ProviderLogo provider={connection!.provider} className="h-4 w-4 shrink-0" />
            ) : null}
            {isCloud ? providerLabel(connection!.provider) : row.kindLabel}
          </span>
          <div className="flex items-center gap-1.5">
            <CategoryChip category={row.category} />
            {isCloud && isOrganizationScope(connection!) ? (
              <span
                className="inline-flex items-center rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-200"
                title="Connections scan fans out across organization member accounts"
                data-testid="connection-org-scope-chip"
              >
                Organization
              </span>
            ) : null}
            {continuous ? (
              <span
                className="inline-flex items-center rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[10px] font-medium text-sky-700 dark:text-sky-200"
                title="Continuous mode: event-driven refresh between full scans"
                data-testid="connection-continuous-chip"
              >
                Continuous
              </span>
            ) : null}
            {mode ? (
              <span
                className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${mode.tone}`}
                title={mode.detail}
                data-testid={
                  mode.label === "Event-driven" ? "connection-event-driven-chip" : undefined
                }
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
      <td className="whitespace-nowrap px-4 py-3 text-ink-secondary">{formatWhen(row.lastScanAt)}</td>
      <td className="px-4 py-3">
        {isCloud ? (
          <div className="flex flex-col gap-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <label className="sr-only" htmlFor={`schedule-${connection!.id}`}>
                Scan schedule
              </label>
              <select
                id={`schedule-${connection!.id}`}
                value={connection!.scan_interval_minutes?.toString() ?? ""}
                disabled={!canUpdate}
                onChange={(event) => onCloudScheduleChange(connection!, event.target.value)}
                className="w-36 rounded-lg border border-outline bg-surface-elevated px-2.5 py-1.5 text-xs text-foreground outline-none transition focus:border-emerald-500 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {SCHEDULE_OPTIONS.map(([label, value]) => (
                  <option key={label} value={value}>
                    {label}
                  </option>
                ))}
              </select>
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-ink-secondary">
                <input
                  type="checkbox"
                  checked={continuous}
                  disabled={!canUpdate}
                  onChange={(event) => onCloudScanModeChange(connection!, event.target.checked)}
                  className="h-3.5 w-3.5 shrink-0 accent-sky-500 disabled:cursor-not-allowed"
                  data-testid="schedule-scan-mode-continuous"
                />
                Continuous
              </label>
            </div>
            {continuous ? (
              <p
                className="max-w-[16rem] text-[10px] leading-snug text-ink-tertiary"
                data-testid="schedule-continuous-queue-hint"
              >
                Mid-interval refresh needs both AGENT_BOM_CONNECTIONS_SCHEDULER=1 and a provider
                event queue env on the control plane.
              </p>
            ) : null}
          </div>
        ) : (
          <span className="tabular-nums text-ink-secondary">
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
              disabled={isBusy || !canManage || !scannable || connection!.status !== "active"}
              title={
                !scannable
                  ? "Scanning for this provider is unavailable"
                  : connection!.status !== "active"
                    ? "Verify this connection before running a scan"
                    : "Run a read-only inventory and CIS scan"
              }
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              {isBusy ? "Working…" : "Run scan"}
            </button>
            <button
              onClick={() => onCloudDelete(connection!)}
              disabled={isBusy || !canDelete}
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
              className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-muted px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-outline-strong"
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
