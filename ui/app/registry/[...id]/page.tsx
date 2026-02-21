"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  ExternalLink,
  Package,
  KeyRound,
  Wrench,
  Bug,
  Info,
  Loader2,
  AlertTriangle,
  Scale,
  Tag,
} from "lucide-react";
import { api, type RegistryServer } from "@/lib/api";

function riskColor(risk: string) {
  switch (risk) {
    case "high": return "text-red-400 bg-red-950 border-red-800";
    case "medium": return "text-yellow-400 bg-yellow-950 border-yellow-800";
    case "low": return "text-emerald-400 bg-emerald-950 border-emerald-800";
    default: return "text-zinc-400 bg-zinc-800 border-zinc-700";
  }
}

function riskBorderColor(risk: string) {
  switch (risk) {
    case "high": return "border-red-800";
    case "medium": return "border-yellow-800";
    case "low": return "border-emerald-800";
    default: return "border-zinc-800";
  }
}

function Section({ title, icon: Icon, children, accent }: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
      <div className={`flex items-center gap-2 mb-3 text-xs font-medium uppercase tracking-wider ${accent || "text-zinc-500"}`}>
        <Icon className="w-3.5 h-3.5" />
        {title}
      </div>
      {children}
    </div>
  );
}

export default function RegistryDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [server, setServer] = useState<RegistryServer | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const serverId = Array.isArray(params.id) ? params.id.join("/") : (params.id || "");

  useEffect(() => {
    if (!serverId) return;
    api
      .getRegistryServer(serverId)
      .then((res) => setServer(res))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [serverId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[80vh] text-zinc-400">
        <Loader2 className="w-5 h-5 animate-spin mr-2" />
        Loading server details...
      </div>
    );
  }

  if (error || !server) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] text-zinc-400 gap-3">
        <AlertTriangle className="w-8 h-8 text-amber-500" />
        <p className="text-sm">{error || "Server not found"}</p>
        <button onClick={() => router.push("/registry")} className="text-xs text-emerald-400 hover:text-emerald-300">
          Back to Registry
        </button>
      </div>
    );
  }

  const tools = server.tools || [];
  const creds = server.credential_env_vars || [];
  const cves = server.known_cves || [];

  return (
    <div className="max-w-4xl mx-auto py-6 space-y-6">
      {/* Back button */}
      <button
        onClick={() => router.push("/registry")}
        className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Registry
      </button>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          {server.verified ? (
            <ShieldCheck className="w-6 h-6 text-emerald-400 mt-0.5 shrink-0" />
          ) : (
            <ShieldAlert className="w-6 h-6 text-zinc-500 mt-0.5 shrink-0" />
          )}
          <div>
            <h1 className="text-2xl font-semibold text-zinc-100">{server.name}</h1>
            <div className="flex items-center gap-2 mt-1 text-sm text-zinc-500">
              <span className="font-mono">{server.publisher}</span>
              {server.packages?.[0]?.ecosystem && (
                <>
                  <span className="text-zinc-700">·</span>
                  <span>{server.packages[0].ecosystem}</span>
                </>
              )}
              {server.license && (
                <>
                  <span className="text-zinc-700">·</span>
                  <Scale className="w-3 h-3" />
                  <span>{server.license}</span>
                </>
              )}
              {server.category && (
                <>
                  <span className="text-zinc-700">·</span>
                  <Tag className="w-3 h-3" />
                  <span>{server.category}</span>
                </>
              )}
            </div>
            {server.description && (
              <p className="text-sm text-zinc-400 mt-2">{server.description}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-xs px-2 py-1 rounded border font-mono uppercase font-medium ${riskColor(server.risk_level)}`}>
            {server.risk_level}
          </span>
          {server.verified && (
            <span className="text-[10px] px-1.5 py-0.5 rounded border font-mono border-emerald-800 bg-emerald-950 text-emerald-400">
              verified
            </span>
          )}
        </div>
      </div>

      {/* Risk Justification */}
      {server.risk_justification && (
        <div className={`rounded-xl border-2 p-4 ${riskBorderColor(server.risk_level)} bg-zinc-900`}>
          <div className="flex items-center gap-2 mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">
            <Info className="w-3.5 h-3.5" />
            Why {server.risk_level} risk?
          </div>
          <p className="text-sm text-zinc-300 leading-relaxed">{server.risk_justification}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Tools */}
        <Section title={`Tools (${tools.length})`} icon={Wrench}>
          {tools.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {tools.map((tool) => (
                <span key={tool} className="px-2 py-1 bg-zinc-800 border border-zinc-700 rounded text-xs font-mono text-zinc-300">
                  {tool}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-zinc-600">No tools documented</p>
          )}
        </Section>

        {/* Credentials */}
        <Section title={`Credentials (${creds.length})`} icon={KeyRound} accent={creds.length > 0 ? "text-amber-500" : undefined}>
          {creds.length > 0 ? (
            <div className="space-y-1.5">
              {creds.map((cred) => (
                <div key={cred} className="flex items-center gap-2 px-2 py-1.5 bg-amber-950/30 border border-amber-900/50 rounded">
                  <KeyRound className="w-3 h-3 text-amber-500 shrink-0" />
                  <code className="text-xs font-mono text-amber-400">{cred}</code>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-zinc-600">No credential environment variables</p>
          )}
        </Section>

        {/* Packages */}
        <Section title="Package" icon={Package}>
          {server.packages?.map((pkg) => (
            <div key={pkg.name} className="space-y-1">
              <code className="text-sm font-mono text-zinc-200">{pkg.name}</code>
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <span className="px-1.5 py-0.5 bg-zinc-800 border border-zinc-700 rounded font-mono">
                  {pkg.ecosystem}
                </span>
                {server.latest_version && (
                  <span>Latest: <span className="text-emerald-400 font-mono">{server.latest_version}</span></span>
                )}
              </div>
            </div>
          ))}
        </Section>

        {/* Known CVEs */}
        <Section title={`Known CVEs (${cves.length})`} icon={Bug} accent={cves.length > 0 ? "text-red-400" : undefined}>
          {cves.length > 0 ? (
            <div className="space-y-1">
              {cves.map((cve) => (
                <a
                  key={cve}
                  href={`https://osv.dev/vulnerability/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 text-xs font-mono text-red-400 hover:text-red-300 transition-colors"
                >
                  <Bug className="w-3 h-3" />
                  {cve}
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              ))}
            </div>
          ) : (
            <p className="text-xs text-zinc-600">No known CVEs for this server</p>
          )}
        </Section>
      </div>

      {/* Source link */}
      {server.source_url && (
        <a
          href={server.source_url}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 text-sm text-emerald-400 hover:text-emerald-300 transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
          {server.source_url}
        </a>
      )}
    </div>
  );
}
