"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { FileSearch, Loader2, Newspaper, RefreshCw, Search, ShieldAlert } from "lucide-react";

import {
  api,
  formatDate,
  type IntelAdvisory,
  type IntelDailyBriefResponse,
  type IntelMatchResponse,
  type IntelSource,
} from "@/lib/api";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { StatStrip } from "@/components/stat-strip";
import { PageErrorState } from "@/components/states/page-state";
import {
  Field,
  INPUT_CLASS,
  InlineNotice,
  PanelButton,
  PanelIntro,
  Pill,
  errorMessage,
} from "@/components/integrations/panel-kit";

function severityTone(sev: string): "danger" | "warn" | "neutral" {
  const s = sev.toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "warn";
  return "neutral";
}

export function IntelPanel() {
  const [sources, setSources] = useState<IntelSource[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await api.getIntelSources();
      setSources(res.sources ?? []);
    } catch (err) {
      setLoadError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return sources;
    return sources.filter(
      (s) =>
        s.display_name.toLowerCase().includes(q) ||
        s.source_id.toLowerCase().includes(q) ||
        s.kind.toLowerCase().includes(q),
    );
  }, [sources, query]);

  const enabledCount = sources.filter((s) => s.enabled).length;
  const totalRecords = sources.reduce((acc, s) => acc + (s.feed_run?.record_count ?? 0), 0);

  const columns = useMemo<DataTableColumn<IntelSource>[]>(
    () => [
      {
        key: "name",
        header: "Source",
        cell: (s) => (
          <div className="min-w-0">
            <div className="truncate font-medium text-[color:var(--foreground)]">{s.display_name}</div>
            <div className="truncate text-xs text-[color:var(--text-tertiary)]">
              {s.kind} · {s.owner}
            </div>
          </div>
        ),
      },
      { key: "tier", header: "Tier", cell: (s) => <Pill tone="neutral">{s.tier}</Pill> },
      {
        key: "validation",
        header: "Validation",
        cell: (s) =>
          s.validation_status === "validated" ? (
            <Pill tone="success">{s.validation_status}</Pill>
          ) : (
            <Pill tone="warn">{s.validation_status || "unknown"}</Pill>
          ),
      },
      {
        key: "records",
        header: "Records",
        align: "right",
        cell: (s) => (
          <span className="font-mono tabular-nums text-[color:var(--text-secondary)]">
            {(s.feed_run?.record_count ?? 0).toLocaleString()}
          </span>
        ),
      },
      {
        key: "synced",
        header: "Last synced",
        cell: (s) => (
          <span className="text-xs text-[color:var(--text-tertiary)]">
            {s.feed_run?.last_synced ? formatDate(s.feed_run.last_synced) : "never"}
          </span>
        ),
      },
    ],
    [],
  );

  if (loadError) {
    return (
      <PageErrorState
        title="Could not load threat-intel sources"
        detail={loadError}
        action={{ label: "Retry", onClick: () => void load() }}
      />
    );
  }

  return (
    <div className="space-y-5">
      <PanelIntro
        title="Threat intel"
        description="Governed intel sources, advisory lookup, a local analyst daily brief, and inventory package matching — all served from the local intel database."
      >
        <PanelButton tone="secondary" onClick={() => void load()} title="Refresh">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </PanelButton>
      </PanelIntro>

      <StatStrip
        items={[
          { label: "Sources", value: sources.length, icon: ShieldAlert },
          { label: "Enabled", value: enabledCount, accent: "success" },
          { label: "Indexed records", value: totalRecords.toLocaleString() },
        ]}
      />

      <div>
        <div className="mb-2 flex items-center gap-2">
          <Search className="h-4 w-4 text-[color:var(--text-tertiary)]" />
          <input
            className={INPUT_CLASS}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sources by name, id, or kind…"
            data-testid="intel-source-search"
          />
        </div>
        <DataTable
          rows={filtered}
          rowKey={(s) => s.source_id}
          columns={columns}
          loading={loading}
          maxHeight="24rem"
          caption="Threat-intel sources"
          empty="No sources match your search."
          data-testid="intel-sources-table"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <AdvisoryLookup />
        <DailyBrief />
      </div>

      <PackageMatch />
    </div>
  );
}

function AdvisoryLookup() {
  const [id, setId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [advisory, setAdvisory] = useState<IntelAdvisory | null>(null);
  const [notFound, setNotFound] = useState(false);

  const lookup = async () => {
    if (!id.trim()) return;
    setLoading(true);
    setError(null);
    setAdvisory(null);
    setNotFound(false);
    try {
      const res = await api.getIntelAdvisory(id.trim());
      if (res.found && res.advisory) setAdvisory(res.advisory);
      else setNotFound(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
      <div className="flex items-center gap-2 text-sm font-medium text-[color:var(--foreground)]">
        <FileSearch className="h-4 w-4" /> Advisory lookup
      </div>
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void lookup();
        }}
      >
        <input
          className={INPUT_CLASS}
          value={id}
          onChange={(e) => setId(e.target.value)}
          placeholder="CVE-2024-3094, GHSA-…, or OSV id"
          data-testid="intel-advisory-input"
        />
        <PanelButton tone="primary" type="submit" disabled={loading || !id.trim()} data-testid="intel-advisory-submit">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
          Look up
        </PanelButton>
      </form>

      {error ? <InlineNotice tone="error">{error}</InlineNotice> : null}
      {notFound ? <InlineNotice tone="info">No advisory found for that identifier.</InlineNotice> : null}
      {advisory ? (
        <div className="space-y-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-3" data-testid="intel-advisory-result">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-[color:var(--foreground)]">{advisory.id}</span>
            <Pill tone={severityTone(advisory.severity)}>{advisory.severity || "unknown"}</Pill>
            {advisory.cvss_score != null ? <Pill tone="neutral">CVSS {advisory.cvss_score}</Pill> : null}
            {advisory.epss_probability != null ? (
              <Pill tone="warn">EPSS {(advisory.epss_probability * 100).toFixed(1)}%</Pill>
            ) : null}
            {advisory.is_kev ? <Pill tone="danger">KEV</Pill> : null}
          </div>
          {advisory.summary ? (
            <p className="text-sm text-[color:var(--text-secondary)]">{advisory.summary}</p>
          ) : null}
          <div className="text-xs text-[color:var(--text-tertiary)]">
            source {advisory.source || "—"}
            {advisory.fixed_version ? ` · fixed in ${advisory.fixed_version}` : ""}
            {advisory.published_at ? ` · published ${formatDate(advisory.published_at)}` : ""}
            {` · ${advisory.affected?.length ?? 0} affected package(s)`}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function DailyBrief() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [brief, setBrief] = useState<IntelDailyBriefResponse | null>(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      setBrief(await api.getIntelDailyBrief({}));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const s = brief?.sections;
  const rows: { label: string; value: number }[] = s
    ? [
        { label: "KEV in last 24h", value: s.kev_last_24h.length },
        { label: "High-EPSS inventory", value: s.high_epss_inventory.length },
        { label: "Vendor advisories", value: s.vendor_advisories.length },
        { label: "IoC telemetry hits", value: s.ioc_telemetry_hits.length },
        { label: "Campaign matches", value: s.campaign_matches.length },
        { label: "Ransomware sector matches", value: s.ransomware_sector_matches.length },
      ]
    : [];

  return (
    <div className="space-y-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium text-[color:var(--foreground)]">
          <Newspaper className="h-4 w-4" /> Daily brief
        </div>
        <PanelButton tone="primary" onClick={() => void run()} disabled={loading} data-testid="intel-brief-submit">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Newspaper className="h-4 w-4" />}
          Generate
        </PanelButton>
      </div>
      {error ? <InlineNotice tone="error">{error}</InlineNotice> : null}
      {brief ? (
        <div className="space-y-2" data-testid="intel-brief-result">
          <div className="text-xs text-[color:var(--text-tertiary)]">
            Generated {formatDate(brief.generated_at)}
          </div>
          <div className="divide-y divide-[color:var(--border-subtle)] rounded-lg border border-[color:var(--border-subtle)]">
            {rows.map((r) => (
              <div key={r.label} className="flex items-center justify-between px-3 py-1.5 text-sm">
                <span className="text-[color:var(--text-secondary)]">{r.label}</span>
                <span className="font-mono tabular-nums text-[color:var(--foreground)]">{r.value}</span>
              </div>
            ))}
          </div>
          {brief.limitations?.length ? (
            <p className="text-xs text-[color:var(--text-tertiary)]">{brief.limitations[0]}</p>
          ) : null}
        </div>
      ) : (
        <p className="text-sm text-[color:var(--text-tertiary)]">
          Generate a local analyst brief (KEV window, high-EPSS inventory) from governed intel sources.
        </p>
      )}
    </div>
  );
}

function PackageMatch() {
  const [ecosystem, setEcosystem] = useState("");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<IntelMatchResponse | null>(null);

  const submit = async () => {
    if (!ecosystem.trim() || !name.trim()) {
      setError("Ecosystem and package name are required.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.matchIntelPackages([
        { ecosystem: ecosystem.trim(), name: name.trim(), version: version.trim() || undefined },
      ]);
      setResult(res);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-3 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5">
      <div className="flex items-center gap-2 text-sm font-medium text-[color:var(--foreground)]">
        <ShieldAlert className="h-4 w-4" /> Match a package to advisory intel
      </div>
      <form
        className="grid gap-3 md:grid-cols-4"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Ecosystem">
          <input className={INPUT_CLASS} value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} placeholder="npm, pypi, …" data-testid="intel-match-ecosystem" />
        </Field>
        <Field label="Name">
          <input className={INPUT_CLASS} value={name} onChange={(e) => setName(e.target.value)} placeholder="package name" data-testid="intel-match-name" />
        </Field>
        <Field label="Version (optional)">
          <input className={INPUT_CLASS} value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.2.3" />
        </Field>
        <div className="flex items-end">
          <PanelButton tone="primary" type="submit" disabled={loading} className="w-full" data-testid="intel-match-submit">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            Match
          </PanelButton>
        </div>
      </form>
      {error ? <InlineNotice tone="error">{error}</InlineNotice> : null}
      {result ? (
        <InlineNotice tone={result.match_count > 0 ? "success" : "info"} data-testid="intel-match-result">
          {result.matched_packages} of {result.submitted} package(s) matched — {result.match_count} advisory
          {result.match_count === 1 ? "" : "ies"} found.
        </InlineNotice>
      ) : null}
    </div>
  );
}
