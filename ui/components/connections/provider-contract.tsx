"use client";

import { formatMode } from "@/components/connections/catalog";
import {
  type DiscoveryProviderContract
} from "@/lib/api";


export function ProviderContractCard({ provider }: { provider: DiscoveryProviderContract }) {
  const trust = provider.trust_contract;
  const capabilities = provider.capabilities;
  const destinations = capabilities.network_destinations ?? capabilities.outbound_destinations;
  const permissions = capabilities.permissions_used;
  const scanModes = capabilities.scan_modes;
  const previewModes = scanModes.slice(0, 3);
  const extraModeCount = scanModes.length - previewModes.length;

  return (
    <div className="rounded-xl border border-outline bg-surface-elevated p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-foreground">{provider.name}</h3>
          <p className="mt-1 truncate font-mono text-[11px] text-ink-tertiary">{provider.source}</p>
        </div>
        <span
          className="shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-medium"
          style={
            trust.supports_scope_zero
              ? {
                  borderColor: "var(--status-success-border)",
                  backgroundColor: "var(--status-success-bg)",
                  color: "var(--status-success)",
                }
              : {
                  borderColor: "var(--border-subtle)",
                  backgroundColor: "var(--surface)",
                  color: "var(--text-secondary)",
                }
          }
        >
          {trust.supports_scope_zero ? "scope-zero" : "direct pull"}
        </span>
      </div>

      <div className="mt-3 flex max-h-14 flex-wrap gap-1.5 overflow-hidden">
        {previewModes.map((mode) => (
          <span
            key={mode}
            className="rounded border border-outline bg-surface px-2 py-0.5 text-[10px] font-mono text-ink-secondary"
          >
            {formatMode(mode)}
          </span>
        ))}
        {extraModeCount > 0 ? (
          <span
            className="rounded border border-outline bg-surface px-2 py-0.5 text-[10px] font-medium text-ink-tertiary"
            title={scanModes.slice(3).map(formatMode).join(", ")}
          >
            +{extraModeCount} mode{extraModeCount === 1 ? "" : "s"}
          </span>
        ) : null}
      </div>

      <div className="mt-4 grid gap-2 text-xs text-ink-secondary sm:grid-cols-2">
        <span>Read-only: {trust.read_only ? "yes" : "no"}</span>
        <span>Agentless: {trust.agentless ? "yes" : "no"}</span>
        <span>Redaction: {formatMode(trust.redaction_status)}</span>
        <span>Residency: {formatMode(trust.data_residency)}</span>
      </div>

      <div className="mt-4 space-y-2 text-xs text-ink-secondary">
        <div>
          <span className="text-ink-tertiary">Permissions used: </span>
          <span className="text-foreground">{permissions.length}</span>
          {permissions.length > 0 ? (
            <span className="ml-1 font-mono text-[11px] text-ink-secondary">
              {permissions.slice(0, 3).join(", ")}
              {permissions.length > 3 ? ` +${permissions.length - 3}` : ""}
            </span>
          ) : null}
        </div>
        <div>
          <span className="text-ink-tertiary">Network: </span>
          <span className="font-mono text-[11px] text-ink-secondary">
            {destinations.length ? destinations.slice(0, 3).join(", ") : "none"}
            {destinations.length > 3 ? ` +${destinations.length - 3}` : ""}
          </span>
        </div>
      </div>
    </div>
  );
}
