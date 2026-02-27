"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  AlertTriangle,
  Lock,
  Database,
  Bot,
  Eye,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import {
  api,
  severityColor,
  severityDot,
  formatDate,
} from "@/lib/api";
import type { GovernanceReport, GovernanceFinding } from "@/lib/api";

export default function GovernancePage() {
  const [report, setReport] = useState<GovernanceReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    api
      .getGovernance(days)
      .then(setReport)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [days]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-500">
        <div className="animate-pulse">Loading governance report...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/50 p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <p className="text-red-300 text-sm">{error}</p>
        <p className="text-zinc-500 text-xs mt-2">
          Governance requires SNOWFLAKE_ACCOUNT env var on the API server.
        </p>
      </div>
    );
  }

  if (!report) return null;

  const filteredFindings = report.findings.filter((f) => {
    if (categoryFilter && f.category !== categoryFilter) return false;
    if (severityFilter && f.severity !== severityFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Eye className="w-6 h-6 text-emerald-400" />
            Governance Posture
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Account: {report.account} | Discovered: {formatDate(report.discovered_at)}
          </p>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300"
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={365}>Last 365 days</option>
        </select>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          icon={AlertTriangle}
          label="Findings"
          value={report.summary.findings}
          color="text-yellow-400"
        />
        <StatCard
          icon={Shield}
          label="Critical"
          value={report.summary.critical_findings}
          color="text-red-400"
        />
        <StatCard
          icon={Database}
          label="Access Records"
          value={report.summary.access_records}
          color="text-blue-400"
        />
        <StatCard
          icon={Lock}
          label="Privilege Grants"
          value={report.summary.privilege_grants}
          color="text-purple-400"
        />
        <StatCard
          icon={Bot}
          label="Agent Usage"
          value={report.summary.agent_usage_records}
          color="text-emerald-400"
        />
      </div>

      {/* Warnings */}
      {report.warnings.length > 0 && (
        <div className="rounded-lg border border-yellow-800/50 bg-yellow-950/20 p-4">
          <p className="text-xs font-medium text-yellow-400 mb-2">Warnings</p>
          {report.warnings.map((w, i) => (
            <p key={i} className="text-xs text-yellow-300/70">{w}</p>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        <FilterButton
          label="All Categories"
          active={categoryFilter === null}
          onClick={() => setCategoryFilter(null)}
        />
        {["access", "privilege", "data_classification", "agent_usage"].map((cat) => (
          <FilterButton
            key={cat}
            label={cat.replace("_", " ")}
            active={categoryFilter === cat}
            onClick={() => setCategoryFilter(cat)}
          />
        ))}
        <span className="w-px bg-zinc-700 mx-1" />
        <FilterButton
          label="All Severities"
          active={severityFilter === null}
          onClick={() => setSeverityFilter(null)}
        />
        {["critical", "high", "medium", "low"].map((sev) => (
          <FilterButton
            key={sev}
            label={sev}
            active={severityFilter === sev}
            onClick={() => setSeverityFilter(sev)}
          />
        ))}
      </div>

      {/* Findings */}
      <div className="space-y-3">
        <h2 className="text-lg font-semibold text-zinc-200">
          Findings ({filteredFindings.length})
        </h2>
        {filteredFindings.length === 0 ? (
          <p className="text-sm text-zinc-500">No findings match the current filters.</p>
        ) : (
          filteredFindings.map((f, i) => <FindingCard key={i} finding={f} />)
        )}
      </div>

      {/* Data tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Elevated Privileges */}
        {report.privilege_grants.filter((g) => g.is_elevated).length > 0 && (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
            <h3 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
              <Lock className="w-4 h-4 text-purple-400" />
              Elevated Privileges
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-zinc-500 border-b border-zinc-800">
                    <th className="text-left py-1.5 pr-3">Role</th>
                    <th className="text-left py-1.5 pr-3">Privilege</th>
                    <th className="text-left py-1.5">Object</th>
                  </tr>
                </thead>
                <tbody>
                  {report.privilege_grants
                    .filter((g) => g.is_elevated)
                    .slice(0, 20)
                    .map((g, i) => (
                      <tr key={i} className="border-b border-zinc-800/50">
                        <td className="py-1.5 pr-3 text-zinc-300 font-mono">{g.grantee}</td>
                        <td className="py-1.5 pr-3 text-red-400">{g.privilege}</td>
                        <td className="py-1.5 text-zinc-500 font-mono truncate max-w-[200px]">
                          {g.object_name}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Data Classifications */}
        {report.data_classifications.length > 0 && (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
            <h3 className="text-sm font-semibold text-zinc-300 mb-3 flex items-center gap-2">
              <Database className="w-4 h-4 text-blue-400" />
              Data Classifications
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-zinc-500 border-b border-zinc-800">
                    <th className="text-left py-1.5 pr-3">Object</th>
                    <th className="text-left py-1.5 pr-3">Tag</th>
                    <th className="text-left py-1.5">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {report.data_classifications.slice(0, 20).map((d, i) => (
                    <tr key={i} className="border-b border-zinc-800/50">
                      <td className="py-1.5 pr-3 text-zinc-300 font-mono truncate max-w-[200px]">
                        {d.object_name}
                        {d.column_name && (
                          <span className="text-zinc-500">.{d.column_name}</span>
                        )}
                      </td>
                      <td className="py-1.5 pr-3 text-amber-400">{d.tag_name}</td>
                      <td className="py-1.5 text-zinc-500">{d.tag_value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-xs text-zinc-500">{label}</span>
      </div>
      <p className="text-2xl font-bold text-zinc-100">{value.toLocaleString()}</p>
    </div>
  );
}

function FilterButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
        active
          ? "bg-zinc-700 text-zinc-100"
          : "bg-zinc-900 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-300"
      }`}
    >
      {label}
    </button>
  );
}

function FindingCard({ finding }: { finding: GovernanceFinding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={`rounded-lg border p-4 cursor-pointer transition-colors ${severityColor(finding.severity)}`}
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <span className={`w-2 h-2 rounded-full mt-1.5 ${severityDot(finding.severity)}`} />
          <div>
            <p className="text-sm font-medium text-zinc-100">{finding.title}</p>
            <p className="text-xs text-zinc-400 mt-0.5">{finding.description}</p>
            <div className="flex gap-2 mt-2">
              <span className="px-2 py-0.5 rounded text-xs bg-zinc-800 text-zinc-400 capitalize">
                {finding.category.replace("_", " ")}
              </span>
              <span className="px-2 py-0.5 rounded text-xs bg-zinc-800 text-zinc-400 capitalize">
                {finding.severity}
              </span>
              {finding.agent_or_role && (
                <span className="px-2 py-0.5 rounded text-xs bg-zinc-800 text-zinc-400 font-mono">
                  {finding.agent_or_role}
                </span>
              )}
            </div>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-zinc-500 flex-shrink-0" />
        ) : (
          <ChevronDown className="w-4 h-4 text-zinc-500 flex-shrink-0" />
        )}
      </div>
      {expanded && Object.keys(finding.details).length > 0 && (
        <div className="mt-3 pl-5 border-t border-zinc-800 pt-3">
          <pre className="text-xs text-zinc-400 whitespace-pre-wrap break-words">
            {JSON.stringify(finding.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
