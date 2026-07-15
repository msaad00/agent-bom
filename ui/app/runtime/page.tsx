"use client";

import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2, Lock, Shield } from "lucide-react";

import ProxyDashboard from "@/app/proxy/ProxyDashboard";
import GatewayPage from "@/app/gateway/GatewayDashboard";
import { RuntimeEmbedProvider } from "@/components/runtime-embed-context";

type RuntimeTab = "proxy" | "gateway";

const TABS: { key: RuntimeTab; label: string; icon: typeof Shield; description: string }[] = [
  {
    key: "proxy",
    label: "Proxy",
    icon: Shield,
    description: "Live MCP proxy telemetry, alerts, and tool-call enforcement evidence.",
  },
  {
    key: "gateway",
    label: "Gateway",
    icon: Lock,
    description: "Gateway policy, fused live feed, audit trail, and evaluate sandbox.",
  },
];

function RuntimeTabs() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const tab: RuntimeTab = searchParams.get("tab") === "gateway" ? "gateway" : "proxy";
  const active = TABS.find((item) => item.key === tab) ?? TABS[0]!;

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 border-b border-[color:var(--border-subtle)] pb-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">Runtime</h1>
          <p className="mt-1 max-w-3xl text-sm text-[color:var(--text-secondary)]">
            One enforcement surface for MCP proxy telemetry and gateway policy. Switch tabs to review live
            activity, alerts, rollout posture, and audit evidence without hopping between nav entries.
          </p>
        </div>
        <div
          className="flex flex-wrap items-center gap-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-0.5"
          role="tablist"
          aria-label="Runtime surface"
        >
          {TABS.map((item) => {
            const Icon = item.icon;
            const selected = item.key === tab;
            return (
              <button
                key={item.key}
                type="button"
                role="tab"
                aria-selected={selected}
                onClick={() => router.replace(`/runtime?tab=${item.key}`)}
                className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  selected
                    ? "bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                    : "text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </button>
            );
          })}
        </div>
      </div>

      <p className="text-xs text-[color:var(--text-tertiary)]">{active.description}</p>

      <RuntimeEmbedProvider>
        {tab === "proxy" ? <ProxyDashboard /> : <GatewayPage />}
      </RuntimeEmbedProvider>
    </div>
  );
}

export default function RuntimePage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-[var(--text-tertiary)]" />
        </div>
      }
    >
      <RuntimeTabs />
    </Suspense>
  );
}
