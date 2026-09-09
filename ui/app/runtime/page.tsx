"use client";

import { Suspense, useId, useRef } from "react";
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
    description: "Managed profiles, resumable gateway activity, policy and audit evidence.",
  },
];

function RuntimeTabs() {
  const tabId = useId();
  const tabButtons = useRef<Array<HTMLButtonElement | null>>([]);
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
          {TABS.map((item, index) => {
            const Icon = item.icon;
            const selected = item.key === tab;
            return (
              <button
                key={item.key}
                type="button"
                role="tab"
                id={`${tabId}-${item.key}`}
                aria-controls={`${tabId}-panel-${item.key}`}
                aria-selected={selected}
                tabIndex={selected ? 0 : -1}
                ref={(button) => { tabButtons.current[index] = button; }}
                onKeyDown={(event) => {
                  const nextIndex = event.key === "ArrowRight" ? (index + 1) % TABS.length
                    : event.key === "ArrowLeft" ? (index - 1 + TABS.length) % TABS.length
                      : event.key === "Home" ? 0
                        : event.key === "End" ? TABS.length - 1 : null;
                  if (nextIndex === null) return;
                  event.preventDefault();
                  router.replace(`/runtime?tab=${TABS[nextIndex]!.key}`);
                  tabButtons.current[nextIndex]?.focus();
                }}
                onClick={() => router.replace(`/runtime?tab=${item.key}`)}
                className={`inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  selected
                    ? "bg-[color:var(--accent-soft)] text-emerald-800 dark:text-emerald-200"
                    : "text-[color:var(--text-secondary)] hover:text-[color:var(--foreground)]"
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

      {TABS.map((item) => (
        <div key={item.key} role="tabpanel" id={`${tabId}-panel-${item.key}`} aria-labelledby={`${tabId}-${item.key}`} hidden={tab !== item.key} tabIndex={0}>
          {tab === item.key ? (
            <RuntimeEmbedProvider>
              {item.key === "proxy" ? <ProxyDashboard /> : <GatewayPage />}
            </RuntimeEmbedProvider>
          ) : null}
        </div>
      ))}
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
