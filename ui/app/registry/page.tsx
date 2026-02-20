"use client";

import { useEffect, useState } from "react";
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  ExternalLink,
  Package,
  KeyRound,
  Wrench,
  Loader2,
  AlertTriangle,
  Filter,
} from "lucide-react";
import { api, type RegistryServer } from "@/lib/api";

type RiskFilter = "all" | "high" | "medium" | "low";

export default function RegistryPage() {
  const [servers, setServers] = useState<RegistryServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    api
      .listRegistry()
      .then((res) => setServers(res.servers))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const filtered = servers.filter((s) => {
    const matchesSearch =
      !search ||
      s.name.toLowerCase().includes(search.toLowerCase()) ||
      s.description?.toLowerCase().includes(search.toLowerCase()) ||
      s.publisher?.toLowerCase().includes(search.toLowerCase());
    const matchesRisk = riskFilter === "all" || s.risk_level === riskFilter;
    return matchesSearch && matchesRisk;
  });

  const riskCounts = {
    all: servers.length,
    high: servers.filter((s) => s.risk_level === "high").length,
    medium: servers.filter((s) => s.risk_level === "medium").length,
    low: servers.filter((s) => s.risk_level === "low").length,
  };

  const riskColor = (risk: string) => {
    switch (risk) {
      case "high": return "text-red-400 bg-red-950 border-red-800";
      case "medium": return "text-yellow-400 bg-yellow-950 border-yellow-800";
      case "low": return "text-emerald-400 bg-emerald-950 border-emerald-800";
      default: return "text-zinc-400 bg-zinc-800 border-zinc-700";
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading MCP registry...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">Could not load MCP registry</p>
        <p className="text-xs text-zinc-500">Make sure the API is running at localhost:8422</p>
      </div>
    );
  }

  return (
    <div className="py-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-zinc-100">MCP Server Registry</h1>
        <p className="text-sm text-zinc-500 mt-1">
          {servers.length} known servers with risk levels, tools, and credential mapping
        </p>
      </div>

      {/* Search + Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
          <input
            type="text"
            placeholder="Search servers, publishers..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-zinc-900 border border-zinc-700 rounded-lg text-sm text-zinc-300 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-600"
          />
        </div>

        <div className="flex items-center gap-1">
          <Filter className="w-3.5 h-3.5 text-zinc-500 mr-1" />
          {(["all", "high", "medium", "low"] as RiskFilter[]).map((r) => (
            <button
              key={r}
              onClick={() => setRiskFilter(r)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                riskFilter === r
                  ? "bg-zinc-700 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"
              }`}
            >
              {r === "all" ? "All" : r.charAt(0).toUpperCase() + r.slice(1)}{" "}
              <span className="text-zinc-500">({riskCounts[r]})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Server Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map((server) => (
          <div
            key={server.id}
            className={`rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 hover:border-zinc-700 transition-colors cursor-pointer ${
              expanded === server.id ? "ring-1 ring-emerald-700" : ""
            }`}
            onClick={() => setExpanded(expanded === server.id ? null : server.id)}
          >
            {/* Top row */}
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2 min-w-0">
                {server.verified ? (
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <ShieldAlert className="w-4 h-4 text-zinc-500 shrink-0" />
                )}
                <span className="font-mono text-sm font-medium text-zinc-200 truncate">
                  {server.name}
                </span>
              </div>
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase shrink-0 ${riskColor(server.risk_level)}`}
              >
                {server.risk_level}
              </span>
            </div>

            {/* Description */}
            {server.description && (
              <p className="text-xs text-zinc-500 mb-2 line-clamp-2">{server.description}</p>
            )}

            {/* Stats row */}
            <div className="flex items-center gap-3 text-[10px] text-zinc-500">
              {server.packages && server.packages.length > 0 && (
                <span className="flex items-center gap-0.5">
                  <Package className="w-2.5 h-2.5" /> {server.packages[0].ecosystem}
                </span>
              )}
              <span className="flex items-center gap-0.5">
                <span>{server.transport}</span>
              </span>
              {server.publisher && (
                <span className="truncate">{server.publisher}</span>
              )}
            </div>

            {/* Expanded details */}
            {expanded === server.id && (
              <div className="mt-3 pt-3 border-t border-zinc-800 space-y-2">
                {server.source_url && (
                  <a
                    href={server.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <ExternalLink className="w-3 h-3" />
                    {server.source_url}
                  </a>
                )}
                {server.packages && server.packages.length > 0 && (
                  <div>
                    <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Packages</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {server.packages.map((p) => (
                        <span
                          key={p.name}
                          className="px-1.5 py-0.5 bg-zinc-800 border border-zinc-700 rounded text-[10px] font-mono text-zinc-400"
                        >
                          {p.name} ({p.ecosystem})
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-zinc-500 text-sm">
          No servers match your search
        </div>
      )}
    </div>
  );
}
