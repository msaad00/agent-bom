"use client";

import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { FileDown, Loader2, Newspaper, Plug, Webhook } from "lucide-react";

import { WebhooksPanel } from "@/components/integrations/webhooks-panel";
import { SiemPanel } from "@/components/integrations/siem-panel";
import { IntelPanel } from "@/components/integrations/intel-panel";
import { ReportsPanel } from "@/components/integrations/reports-panel";

type IntegrationsTab = "webhooks" | "siem" | "intel" | "reports";

const TABS: { key: IntegrationsTab; label: string; icon: typeof Webhook }[] = [
  { key: "webhooks", label: "Webhooks", icon: Webhook },
  { key: "siem", label: "SIEM", icon: Plug },
  { key: "intel", label: "Threat Intel", icon: Newspaper },
  { key: "reports", label: "Reports", icon: FileDown },
];

function isTab(value: string | null): value is IntegrationsTab {
  return value === "webhooks" || value === "siem" || value === "intel" || value === "reports";
}

function IntegrationsTabs() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const raw = searchParams.get("tab");
  const tab: IntegrationsTab = isTab(raw) ? raw : "webhooks";

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-[color:var(--foreground)]">
          Operations &amp; Integrations
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-[color:var(--text-secondary)]">
          Manage the outbound integrations and operational surfaces that ship with the control plane —
          webhook subscriptions, SIEM connectors, threat-intel lookups, and async report exports. Every
          capability here is also available to agents over REST and MCP.
        </p>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-[color:var(--border-subtle)] pb-4">
        {TABS.map((item) => {
          const Icon = item.icon;
          const selected = item.key === tab;
          return (
            <button
              key={item.key}
              type="button"
              onClick={() => router.replace(`/integrations?tab=${item.key}`)}
              aria-pressed={selected}
              className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition-colors ${
                selected
                  ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                  : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
              }`}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </button>
          );
        })}
      </div>

      {tab === "webhooks" ? <WebhooksPanel /> : null}
      {tab === "siem" ? <SiemPanel /> : null}
      {tab === "intel" ? <IntelPanel /> : null}
      {tab === "reports" ? <ReportsPanel /> : null}
    </div>
  );
}

export default function IntegrationsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-[40vh] items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-[color:var(--text-tertiary)]" />
        </div>
      }
    >
      <IntegrationsTabs />
    </Suspense>
  );
}
