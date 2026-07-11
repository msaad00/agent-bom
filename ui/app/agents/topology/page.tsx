"use client";

/**
 * Agent trust mesh — MCP topology for engineers.
 * Kept off Overview (exec briefing); linked from Agents and Overview CTAs.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { api, type Agent } from "@/lib/api";
import { AgentTopology } from "@/components/agent-topology";
import { useAuthState } from "@/components/auth-provider";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { FIRST_SCAN_ACTIONS } from "@/lib/empty-state-actions";

export default function AgentTopologyPage() {
  const { session } = useAuthState();
  const [agents, setAgents] = useState<Agent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .listAgents()
      .then((res) => {
        if (!cancelled) setAgents(Array.isArray(res?.agents) ? res.agents : []);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load agents");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return <PageErrorState title="Could not load agent topology" detail={error} />;
  }
  if (agents == null) {
    return (
      <PageLoadingState
        title="Loading agent topology"
        detail="Building the trust mesh from scanned AI runtimes and MCP services."
      />
    );
  }
  if (agents.length === 0) {
    return (
      <PageEmptyState
        title="No agents to map yet"
        detail="Run a local or repo scan to inventory AI runtimes and MCP services, then open the trust mesh."
        actions={FIRST_SCAN_ACTIONS}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link
            href="/agents"
            className="mb-2 inline-flex items-center gap-1 text-xs text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
          >
            <ArrowLeft className="h-3 w-3" /> Agents
          </Link>
          <h1 className="text-lg font-semibold text-[color:var(--foreground)]">Agent topology</h1>
          <p className="mt-1 max-w-2xl text-sm text-[color:var(--text-secondary)]">
            Trust mesh of scanned AI runtimes and MCP services. Amber edges are credentials; red edges
            are CVE evidence. Overview stays the exec briefing — this page is for engineer drill-down.
          </p>
        </div>
        <Link
          href="/context"
          className="text-xs text-emerald-500 hover:text-emerald-400"
        >
          Context map →
        </Link>
      </div>
      <AgentTopology agents={agents} session={session} />
    </div>
  );
}
