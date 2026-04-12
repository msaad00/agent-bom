"use client";

/**
 * Activity Feed — real-time sidebar showing recent scan events.
 * Polls scan jobs and converts them into a chronological activity stream.
 */

import { useEffect, useState, useMemo } from "react";
import { api } from "@/lib/api";
import type { JobListItem } from "@/lib/api";
import {
  Search,
  CheckCircle,
  XCircle,
} from "lucide-react";

// ── Activity event types ────────────────────────────────────────────────────

type ActivityType = "scan_started" | "scan_completed" | "scan_failed";

interface ActivityEvent {
  id: string;
  type: ActivityType;
  message: string;
  timestamp: string;
  meta?: {
    job_id?: string;
    cve_count?: number;
    critical_count?: number;
  };
}

const TYPE_ICONS: Record<ActivityType, React.ElementType> = {
  scan_started: Search,
  scan_completed: CheckCircle,
  scan_failed: XCircle,
};

const TYPE_COLORS: Record<ActivityType, string> = {
  scan_started: "text-blue-400",
  scan_completed: "text-emerald-400",
  scan_failed: "text-red-400",
};

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function jobsToEvents(jobs: JobListItem[]): ActivityEvent[] {
  const events: ActivityEvent[] = [];
  for (const job of jobs) {
    events.push({
      id: `${job.job_id}-start`,
      type: "scan_started",
      message: "Scan started",
      timestamp: job.created_at,
      meta: { job_id: job.job_id },
    });
    if (job.status === "done" && job.completed_at) {
      const findingCount = job.summary?.total_vulnerabilities ?? 0;
      const critCount = job.summary?.critical_findings ?? 0;
      const message =
        job.summary == null
          ? "Scan completed"
          : `Scan completed: ${findingCount} findings${critCount > 0 ? `, ${critCount} critical` : ""}`;
      events.push({
        id: `${job.job_id}-done`,
        type: "scan_completed",
        message,
        timestamp: job.completed_at,
        meta: {
          job_id: job.job_id,
          cve_count: findingCount,
          critical_count: critCount,
        },
      });
    } else if (job.status === "failed" && job.completed_at) {
      events.push({
        id: `${job.job_id}-fail`,
        type: "scan_failed",
        message: `Scan failed: ${job.error ?? "unknown error"}`,
        timestamp: job.completed_at,
        meta: { job_id: job.job_id },
      });
    }
  }
  return events.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

// ── Component ───────────────────────────────────────────────────────────────

interface ActivityFeedProps {
  maxItems?: number;
  className?: string;
  initialJobs?: JobListItem[];
  refresh?: boolean;
}

export function ActivityFeed({
  maxItems = 20,
  className,
  initialJobs = [],
  refresh = true,
}: ActivityFeedProps) {
  const [jobs, setJobs] = useState<JobListItem[]>(initialJobs);
  const [filter, setFilter] = useState<ActivityType | "all">("all");
  const [loading, setLoading] = useState(refresh && initialJobs.length === 0);

  useEffect(() => {
    if (initialJobs.length > 0) {
      setJobs(initialJobs);
      setLoading(false);
    }
  }, [initialJobs]);

  useEffect(() => {
    if (!refresh) {
      setLoading(false);
      return;
    }

    async function load() {
      try {
        const jobsRes = await api.listJobs();
        setJobs(jobsRes.jobs.slice(0, 20));
      } catch {
        /* ignore */
      } finally {
        setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

  const events = useMemo(() => jobsToEvents(jobs), [jobs]);
  const filtered = useMemo(
    () =>
      (filter === "all"
        ? events
        : events.filter((e) => e.type === filter)
      ).slice(0, maxItems),
    [events, filter, maxItems]
  );

  return (
    <div
      className={`bg-zinc-900 border border-zinc-800 rounded-xl ${className ?? ""}`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <h3 className="text-sm font-semibold text-zinc-300">Activity</h3>
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as ActivityType | "all")}
          className="text-xs bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-zinc-400"
        >
          <option value="all">All</option>
          <option value="scan_started">Scans</option>
          <option value="scan_completed">Completed</option>
          <option value="scan_failed">Failures</option>
        </select>
      </div>

      {/* Event list */}
      <div className="divide-y divide-zinc-800 max-h-[400px] overflow-y-auto">
        {loading ? (
          <div className="p-4 text-center text-zinc-600 text-xs">
            Loading...
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-4 text-center text-zinc-600 text-xs">
            No activity yet
          </div>
        ) : (
          filtered?.map((event) => {
            const Icon = TYPE_ICONS[event.type];
            const color = TYPE_COLORS[event.type];
            return (
              <div
                key={event.id}
                className="flex items-start gap-3 px-4 py-3 hover:bg-zinc-800/50 transition-colors"
              >
                <Icon
                  className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${color}`}
                />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-zinc-300 leading-tight truncate">
                    {event.message}
                  </p>
                  <p className="text-[10px] text-zinc-600 mt-0.5">
                    {timeAgo(event.timestamp)}
                  </p>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
