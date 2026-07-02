"use client";

import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2, Lock, Shield } from "lucide-react";

import ProxyDashboard from "@/app/proxy/page";
import GatewayPage from "@/app/gateway/page";

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
    <div className="space-y-6">
      <div className="flex flex-col gap-4 border-b border-zinc-800 pb-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-100">Runtime</h1>
          <p className="mt-1 max-w-3xl text-sm text-zinc-400">
            One enforcement surface for MCP proxy telemetry and gateway policy. Switch tabs to review live
            activity, alerts, rollout posture, and audit evidence without hopping between nav entries.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {TABS.map((item) => {
            const Icon = item.icon;
            const selected = item.key === tab;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => router.replace(`/runtime?tab=${item.key}`)}
                className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition-colors ${
                  selected
                    ? "border-emerald-700 bg-emerald-950/40 text-emerald-200"
                    : "border-zinc-800 bg-zinc-950 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
                }`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </button>
            );
          })}
        </div>
      </div>

      <p className="text-xs text-zinc-500">{active.description}</p>

      {tab === "proxy" ? <ProxyDashboard /> : <GatewayPage />}
    </div>
  );
}

export default function RuntimePage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-zinc-500" />
        </div>
      }
    >
      <RuntimeTabs />
    </Suspense>
  );
}
