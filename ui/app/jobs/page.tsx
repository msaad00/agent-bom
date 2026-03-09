"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, JobStatus, formatDate } from "@/lib/api";
import { ShieldAlert, Clock, CheckCircle2, XCircle, Loader2, Trash2 } from "lucide-react";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";

interface JobSummary {
  job_id: string;
  status: JobStatus;
  created_at: string;
  completed_at?: string;
}

function StatusIcon({ status }: { status: JobStatus }) {
  switch (status) {
    case "done":
      return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-red-400" />;
    case "running":
      return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />;
    case "cancelled":
      return <XCircle className="w-4 h-4 text-zinc-500" />;
    default:
      return <Clock className="w-4 h-4 text-zinc-500" />;
  }
}

function statusLabel(s: JobStatus) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function statusColor(s: JobStatus) {
  switch (s) {
    case "done":      return "text-emerald-400";
    case "failed":    return "text-red-400";
    case "running":   return "text-blue-400";
    case "cancelled": return "text-zinc-500";
    default:          return "text-zinc-400";
  }
}

export default function JobsPage() {
  const router = useRouter();
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError("");
    api.listJobs()
      .then((r) => setJobs(r.jobs))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  async function handleDelete(jobId: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    setDeleting(jobId);
    try {
      await api.deleteScan(jobId);
      setJobs((prev) => prev.filter((j) => j.job_id !== jobId));
    } finally {
      setDeleting(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Jobs</h1>
          <p className="text-zinc-400 text-sm mt-1">Scan job history</p>
        </div>
        <Link
          href="/scan"
          className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          New Scan
        </Link>
      </div>

      {loading && <p className="text-zinc-500 text-sm">Loading jobs…</p>}
      {error && (
        <div className="flex items-center gap-3 p-3 bg-red-950/30 border border-red-800/40 rounded-lg">
          <p className="text-red-400 text-sm flex-1">{error}</p>
          <button onClick={load} className="text-xs text-zinc-400 hover:text-zinc-200 px-2 py-1 border border-zinc-700 rounded">Retry</button>
        </div>
      )}

      {!loading && jobs.length === 0 && (
        <div className="text-center py-16 border border-dashed border-zinc-800 rounded-xl">
          <Clock className="w-8 h-8 text-zinc-700 mx-auto mb-3" />
          <p className="text-zinc-500 text-sm">No scan jobs yet.</p>
          <p className="text-zinc-600 text-xs mt-1">
            <Link href="/scan" className="text-emerald-500 hover:text-emerald-400">Run your first scan</Link> to see results here.
          </p>
        </div>
      )}

      {jobs.length > 0 && (() => {
        const STATUS_COLORS: Record<string, string> = { done: "#22c55e", failed: "#ef4444", running: "#3b82f6", cancelled: "#71717a", pending: "#a1a1aa" };
        const counts: Record<string, number> = {};
        for (const j of jobs) counts[j.status] = (counts[j.status] ?? 0) + 1;
        const pieData = Object.entries(counts).map(([status, value]) => ({ status, value, fill: STATUS_COLORS[status] ?? "#71717a" }));
        return (
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 flex items-center gap-8">
            <div className="w-28 h-28 flex-shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" innerRadius="55%" outerRadius="85%" paddingAngle={2} stroke="none">
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} fillOpacity={0.85} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#09090b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} itemStyle={{ color: "#e4e4e7" }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-2">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide mb-3">Job Status</p>
              {pieData.map((d) => (
                <div key={d.status} className="flex items-center gap-2 text-xs">
                  <span className="w-2 h-2 rounded-full" style={{ background: d.fill }} />
                  <span className="capitalize text-zinc-300 w-20">{d.status}</span>
                  <span className="font-mono text-zinc-500">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {jobs.length > 0 && (
        <div className="border border-zinc-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-zinc-900 border-b border-zinc-800">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Job ID</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Started</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-zinc-500 uppercase tracking-wide">Completed</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800 bg-zinc-950">
              {jobs.map((job) => (
                <tr
                  key={job.job_id}
                  className="hover:bg-zinc-900 transition-colors cursor-pointer group"
                  onClick={() => router.push(`/scan?id=${job.job_id}`)}
                >
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-zinc-300">
                      {job.job_id.slice(0, 8)}…
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className={`flex items-center gap-1.5 ${statusColor(job.status)}`}>
                      <StatusIcon status={job.status} />
                      <span className="text-xs font-medium">{statusLabel(job.status)}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-500">
                    {formatDate(job.created_at)}
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-500">
                    {job.completed_at ? formatDate(job.completed_at) : "—"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => handleDelete(job.job_id, e)}
                      disabled={deleting === job.job_id}
                      className="opacity-0 group-hover:opacity-100 p-1 text-zinc-600 hover:text-red-400 transition-all rounded"
                      title="Delete job"
                    >
                      {deleting === job.job_id
                        ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        : <Trash2 className="w-3.5 h-3.5" />
                      }
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
