"use client";

import { Suspense, useCallback, useEffect, useState, useMemo } from "react";
import {
  api,
  RemediationItem,
  severityColor,
  severityDot,
} from "@/lib/api";
import {
  Wrench,
  Download,
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Loader2,
  Ticket,
} from "lucide-react";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type FrameworkFilter = "all" | "owasp" | "atlas";

const PAGE_SIZE = 25;

// ─── Compliance Impact Summary ────────────────────────────────────────────────

function complianceImpact(items: RemediationItem[], topN = 5) {
  const top = items.slice(0, topN);
  const controlSet = new Set<string>();
  const frameworkSet = new Set<string>();

  for (const item of top) {
    for (const tag of item.owasp_tags ?? []) {
      controlSet.add(tag);
      frameworkSet.add("OWASP");
    }
    for (const tag of item.atlas_tags ?? []) {
      controlSet.add(tag);
      frameworkSet.add("MITRE ATLAS");
    }
  }

  return { controls: controlSet.size, frameworks: frameworkSet.size };
}

// ─── Sort button ──────────────────────────────────────────────────────────────

type SortKey = "impact_score" | "severity" | "agents" | "credentials";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

function SortButton({
  label,
  field,
  current,
  dir,
  onClick,
}: {
  label: string;
  field: SortKey;
  current: SortKey;
  dir: "asc" | "desc";
  onClick: (f: SortKey) => void;
}) {
  const active = current === field;
  return (
    <button
      onClick={() => onClick(field)}
      className={`flex items-center gap-0.5 text-xs font-medium uppercase tracking-wide transition-colors ${
        active ? "text-zinc-200" : "text-zinc-500 hover:text-zinc-300"
      }`}
    >
      {label}
      {active ? (
        dir === "desc" ? (
          <ChevronDown className="w-3 h-3" />
        ) : (
          <ChevronUp className="w-3 h-3" />
        )
      ) : null}
    </button>
  );
}

// ─── Row expand / risk narrative ─────────────────────────────────────────────

function NarrativeRow({
  item,
  onCreateJira,
}: {
  item: RemediationItem;
  onCreateJira: (item: RemediationItem) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  const allTags = [...(item.owasp_tags ?? []), ...(item.atlas_tags ?? [])];

  return (
    <>
      <tr className="hover:bg-zinc-900 transition-colors">
        {/* Package */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <span
              className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${severityDot(
                item.severity
              )}`}
            />
            <div>
              <span className="font-mono text-xs text-zinc-200">
                {item.package}
              </span>
              <span className="text-zinc-600 text-xs mx-1">
                {item.current_version}
              </span>
              {item.fixed_version && (
                <>
                  <span className="text-zinc-600 text-xs">→</span>
                  <span className="font-mono text-xs text-emerald-500 ml-1">
                    {item.fixed_version}
                  </span>
                </>
              )}
              {!item.fixed_version && (
                <span className="text-xs text-zinc-600 ml-1">no fix yet</span>
              )}
            </div>
          </div>
        </td>

        {/* Severity */}
        <td className="px-4 py-3">
          <span
            className={`text-xs font-medium px-2 py-0.5 rounded border ${severityColor(
              item.severity
            )}`}
          >
            {item.severity}
          </span>
          {item.is_kev && (
            <span className="ml-1.5 text-xs font-mono bg-red-950 border border-red-800 text-red-400 rounded px-1.5 py-0.5">
              KEV
            </span>
          )}
        </td>

        {/* Impact score */}
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="w-16 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  item.impact_score >= 8
                    ? "bg-red-500"
                    : item.impact_score >= 6
                    ? "bg-orange-500"
                    : item.impact_score >= 4
                    ? "bg-yellow-500"
                    : "bg-blue-500"
                }`}
                style={{ width: `${(item.impact_score / 10) * 100}%` }}
              />
            </div>
            <span className="text-xs font-mono text-zinc-300">
              {item.impact_score.toFixed(1)}
            </span>
          </div>
        </td>

        {/* Agents */}
        <td className="px-4 py-3 text-xs text-zinc-400">
          {item.affected_agents?.length ?? 0}
        </td>

        {/* Credentials */}
        <td className="px-4 py-3 text-xs text-zinc-400">
          {item.exposed_credentials?.length ?? 0}
        </td>

        {/* Compliance tags */}
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-1">
            {allTags.slice(0, 3).map((tag) => (
              <span
                key={tag}
                className="text-[10px] font-mono bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-400"
              >
                {tag}
              </span>
            ))}
            {allTags.length > 3 && (
              <span className="text-[10px] text-zinc-600">
                +{allTags.length - 3}
              </span>
            )}
          </div>
        </td>

        {/* Risk narrative toggle */}
        <td className="px-4 py-3">
          {item.risk_narrative ? (
            <button
              onClick={() => setExpanded((v) => !v)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              {expanded ? (
                <ChevronUp className="w-3 h-3" />
              ) : (
                <ChevronDown className="w-3 h-3" />
              )}
              Narrative
            </button>
          ) : (
            <span className="text-xs text-zinc-600">—</span>
          )}
        </td>

        {/* Actions */}
        <td className="px-4 py-3">
          <button
            onClick={() => onCreateJira(item)}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-zinc-100 transition-colors"
            title="Create Jira ticket"
          >
            <Ticket className="w-3 h-3" />
            Jira
          </button>
        </td>
      </tr>

      {/* Expanded narrative */}
      {expanded && item.risk_narrative && (
        <tr className="bg-zinc-900/50">
          <td colSpan={8} className="px-6 py-3">
            <div className="text-xs text-zinc-400 leading-relaxed border-l-2 border-emerald-800 pl-3">
              {item.risk_narrative}
            </div>
            {(item.reachable_tools?.length ?? 0) > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                <span className="text-[10px] text-zinc-600 uppercase tracking-wide font-medium mr-1">
                  Reachable tools:
                </span>
                {item.reachable_tools.map((t) => (
                  <span
                    key={t}
                    className="text-[10px] font-mono bg-zinc-800 border border-zinc-700 rounded px-1.5 py-0.5 text-zinc-500"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Jira modal ───────────────────────────────────────────────────────────────

function JiraModal({
  item,
  onClose,
}: {
  item: RemediationItem;
  onClose: () => void;
}) {
  const [jiraUrl, setJiraUrl] = useState("");
  const [email, setEmail] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [projectKey, setProjectKey] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      const res = await api.createJiraTicket({
        jira_url: jiraUrl,
        email,
        api_token: apiToken,
        project_key: projectKey,
        finding: {
          package: item.package,
          current_version: item.current_version,
          fixed_version: item.fixed_version,
          severity: item.severity,
          impact_score: item.impact_score,
          affected_agents: item.affected_agents,
          exposed_credentials: item.exposed_credentials,
          risk_narrative: item.risk_narrative,
          owasp_tags: item.owasp_tags,
          atlas_tags: item.atlas_tags,
        },
      });
      setResult(res.ticket_key);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create ticket");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative w-full max-w-md bg-zinc-900 border border-zinc-700/60 rounded-xl shadow-2xl overflow-hidden">
        <div className="px-5 py-4 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-100">
            Create Jira Ticket
          </h2>
          <p className="text-xs text-zinc-500 mt-0.5">
            {item.package} {item.current_version}
          </p>
        </div>

        {result ? (
          <div className="px-5 py-6 text-center">
            <p className="text-sm text-emerald-400 font-medium">
              Ticket created: {result}
            </p>
            <button
              onClick={onClose}
              className="mt-4 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-sm rounded-lg transition-colors"
            >
              Close
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="px-5 py-4 space-y-3">
            {[
              {
                id: "jiraUrl",
                label: "Jira URL",
                val: jiraUrl,
                set: setJiraUrl,
                type: "url",
                placeholder: "https://yourorg.atlassian.net",
              },
              {
                id: "email",
                label: "Email",
                val: email,
                set: setEmail,
                type: "email",
                placeholder: "you@example.com",
              },
              {
                id: "apiToken",
                label: "API Token",
                val: apiToken,
                set: setApiToken,
                type: "password",
                placeholder: "••••••••",
              },
              {
                id: "projectKey",
                label: "Project Key",
                val: projectKey,
                set: setProjectKey,
                type: "text",
                placeholder: "SEC",
              },
            ].map(({ id, label, val, set, type, placeholder }) => (
              <div key={id}>
                <label className="block text-xs text-zinc-400 mb-1">
                  {label}
                </label>
                <input
                  type={type}
                  value={val}
                  onChange={(e) => set(e.target.value)}
                  placeholder={placeholder}
                  required
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-1.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
                />
              </div>
            ))}

            {error && <p className="text-xs text-red-400">{error}</p>}

            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {submitting && <Loader2 className="w-3 h-3 animate-spin" />}
                Create Ticket
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ─── Main page wrapper ────────────────────────────────────────────────────────

export default function RemediationPageWrapper() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-20 text-zinc-400">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading remediation plan...
        </div>
      }
    >
      <RemediationPage />
    </Suspense>
  );
}

function RemediationPage() {
  const [items, setItems] = useState<RemediationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [frameworkFilter, setFrameworkFilter] =
    useState<FrameworkFilter>("all");
  const [fixableOnly, setFixableOnly] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("impact_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [jiraItem, setJiraItem] = useState<RemediationItem | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const jobsResp = await api.listJobs();
      const doneJob = jobsResp.jobs
        .filter((j) => j.status === "done")
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() -
            new Date(a.created_at).getTime()
        )[0];

      if (!doneJob) {
        setItems([]);
        return;
      }

      const remediation = await api.getRemediation(doneJob.job_id);
      setItems(remediation);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  function handleSort(field: SortKey) {
    if (sortKey === field) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortKey(field);
      setSortDir("desc");
    }
  }

  const displayed = useMemo(() => {
    let list = items;

    if (severityFilter !== "all") {
      list = list.filter(
        (i) => i.severity.toLowerCase() === severityFilter
      );
    }
    if (frameworkFilter === "owasp") {
      list = list.filter((i) => (i.owasp_tags?.length ?? 0) > 0);
    } else if (frameworkFilter === "atlas") {
      list = list.filter((i) => (i.atlas_tags?.length ?? 0) > 0);
    }
    if (fixableOnly) {
      list = list.filter((i) => !!i.fixed_version);
    }

    list = [...list].sort((a, b) => {
      let diff = 0;
      if (sortKey === "impact_score") {
        diff = a.impact_score - b.impact_score;
      } else if (sortKey === "severity") {
        diff =
          (SEVERITY_ORDER[a.severity.toLowerCase()] ?? 0) -
          (SEVERITY_ORDER[b.severity.toLowerCase()] ?? 0);
      } else if (sortKey === "agents") {
        diff =
          (a.affected_agents?.length ?? 0) -
          (b.affected_agents?.length ?? 0);
      } else if (sortKey === "credentials") {
        diff =
          (a.exposed_credentials?.length ?? 0) -
          (b.exposed_credentials?.length ?? 0);
      }
      return sortDir === "desc" ? -diff : diff;
    });

    return list;
  }, [items, severityFilter, frameworkFilter, fixableOnly, sortKey, sortDir]);

  // Reset page on filter/sort change
  useEffect(() => {
    setPage(1);
  }, [severityFilter, frameworkFilter, fixableOnly, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(displayed.length / PAGE_SIZE));
  const paged = displayed.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const i of items) {
      const s = i.severity.toLowerCase() as keyof typeof c;
      if (s in c) c[s]++;
    }
    return c;
  }, [items]);

  const impact = useMemo(() => complianceImpact(displayed), [displayed]);

  const SEVERITY_FILTERS: {
    key: SeverityFilter;
    label: string;
    color: string;
  }[] = [
    {
      key: "all",
      label: `All (${items.length})`,
      color: "text-zinc-300",
    },
    {
      key: "critical",
      label: `Critical (${counts.critical})`,
      color: "text-red-400",
    },
    {
      key: "high",
      label: `High (${counts.high})`,
      color: "text-orange-400",
    },
    {
      key: "medium",
      label: `Medium (${counts.medium})`,
      color: "text-yellow-400",
    },
    { key: "low", label: `Low (${counts.low})`, color: "text-blue-400" },
  ];

  const FRAMEWORK_FILTERS: {
    key: FrameworkFilter;
    label: string;
  }[] = [
    { key: "all", label: "All Frameworks" },
    { key: "owasp", label: "OWASP" },
    { key: "atlas", label: "MITRE ATLAS" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Remediation
          </h1>
          <p className="text-zinc-400 text-sm mt-1">
            {items.length} packages ranked by blast-radius impact score
          </p>
        </div>
        {items.length > 0 && (
          <button
            onClick={() =>
              downloadJson(
                displayed,
                `remediation-plan-${new Date().toISOString().slice(0, 10)}.json`
              )
            }
            className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-sm font-medium rounded-lg transition-colors"
            title="Export remediation plan as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            Export
          </button>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-20 text-zinc-400">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading remediation plan...
        </div>
      )}

      {/* Error */}
      {!loading && error && (
        <div className="text-center py-12 border border-dashed border-zinc-800 rounded-xl">
          <p className="text-red-400 text-sm mb-3">{error}</p>
          <button
            onClick={load}
            className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-sm rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {/* Empty */}
      {!loading && !error && items.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Wrench className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">
            Run a scan to see remediation recommendations
          </p>
          <p className="text-zinc-600 text-xs mt-1">
            Remediation plans are generated automatically after each completed
            scan.
          </p>
        </div>
      )}

      {/* Content */}
      {!loading && !error && items.length > 0 && (
        <>
          {/* Compliance impact summary */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl px-5 py-4">
            <p className="text-sm text-zinc-300">
              <span className="font-semibold text-emerald-400">
                Fixing the top 5 packages
              </span>{" "}
              clears{" "}
              <span className="font-semibold text-zinc-100">
                {impact.controls} controls
              </span>{" "}
              across{" "}
              <span className="font-semibold text-zinc-100">
                {impact.frameworks} framework
                {impact.frameworks !== 1 ? "s" : ""}
              </span>
            </p>
            <p className="text-xs text-zinc-600 mt-1">
              Based on OWASP LLM Top 10 and MITRE ATLAS tags assigned to each
              remediation item.
            </p>
          </div>

          {/* Filters */}
          <div className="flex flex-col gap-3">
            <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center justify-between">
              {/* Severity filter */}
              <div className="flex items-center gap-1 flex-wrap">
                {SEVERITY_FILTERS.map(({ key, label, color }) => (
                  <button
                    key={key}
                    onClick={() => setSeverityFilter(key)}
                    className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                      severityFilter === key
                        ? `${color} border-zinc-600 bg-zinc-800`
                        : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {/* Framework filter + fixable toggle */}
              <div className="flex items-center gap-2 flex-wrap">
                {FRAMEWORK_FILTERS.map(({ key, label }) => (
                  <button
                    key={key}
                    onClick={() => setFrameworkFilter(key)}
                    className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                      frameworkFilter === key
                        ? "text-zinc-200 border-zinc-600 bg-zinc-800"
                        : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                    }`}
                  >
                    {label}
                  </button>
                ))}
                <button
                  onClick={() => setFixableOnly((v) => !v)}
                  className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                    fixableOnly
                      ? "text-emerald-400 border-emerald-800 bg-emerald-950/40"
                      : "text-zinc-500 border-zinc-800 hover:border-zinc-700 hover:text-zinc-300"
                  }`}
                >
                  Fixable only
                </button>
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="border border-zinc-800 rounded-xl overflow-hidden overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-zinc-900 border-b border-zinc-800">
                <tr>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">
                    Package
                  </th>
                  <th className="text-left px-4 py-3">
                    <SortButton
                      label="Severity"
                      field="severity"
                      current={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  </th>
                  <th className="text-left px-4 py-3">
                    <SortButton
                      label="Impact"
                      field="impact_score"
                      current={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  </th>
                  <th className="text-left px-4 py-3">
                    <SortButton
                      label="Agents"
                      field="agents"
                      current={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  </th>
                  <th className="text-left px-4 py-3">
                    <SortButton
                      label="Credentials"
                      field="credentials"
                      current={sortKey}
                      dir={sortDir}
                      onClick={handleSort}
                    />
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">
                    Compliance
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">
                    Narrative
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-zinc-950">
                {paged.map((item) => (
                  <NarrativeRow
                    key={`${item.package}-${item.current_version}`}
                    item={item}
                    onCreateJira={setJiraItem}
                  />
                ))}
              </tbody>
            </table>

            {paged.length === 0 && (
              <div className="px-4 py-8 text-center text-zinc-600 text-sm">
                No items match your filters.
              </div>
            )}
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className="text-xs text-zinc-600">
              Page {page} of {totalPages} ({displayed.length} total)
            </p>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-3 h-3" />
                Prev
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-md border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        </>
      )}

      {/* Jira modal */}
      {jiraItem && (
        <JiraModal item={jiraItem} onClose={() => setJiraItem(null)} />
      )}
    </div>
  );
}
