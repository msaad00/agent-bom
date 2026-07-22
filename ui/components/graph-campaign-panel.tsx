"use client";

import type { GraphAttackCampaign } from "@/lib/api-types";

/**
 * Crown-jewel fusion clusters beside the ranked path queue.
 * Distinct from remediation ticket "campaigns" on /remediation.
 */
export function GraphCampaignPanel({
  campaigns,
  selectedCampaignId,
  onSelect,
}: {
  campaigns: GraphAttackCampaign[];
  selectedCampaignId?: string | null;
  onSelect: (campaign: GraphAttackCampaign) => void;
}) {
  if (campaigns.length === 0) return null;

  return (
    <section
      data-testid="graph-campaign-panel"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-[color:var(--foreground)]">
            Crown-jewel clusters
          </h2>
          <p className="mt-1 text-xs text-[color:var(--text-tertiary)]">
            Fusion path groups converging on one high-value asset. Not remediation
            ticket campaigns.
          </p>
        </div>
        <span className="rounded-lg border border-[color:var(--border-subtle)] px-2 py-1 font-mono text-xs text-[color:var(--text-secondary)]">
          {campaigns.length}
        </span>
      </div>
      <ul className="mt-3 space-y-2">
        {campaigns.map((campaign) => {
          const active = campaign.campaign_id === selectedCampaignId;
          return (
            <li key={campaign.campaign_id}>
              <button
                type="button"
                aria-pressed={active}
                onClick={() => onSelect(campaign)}
                className={`w-full rounded-xl border px-3 py-2.5 text-left transition ${
                  active
                    ? "border-violet-500/50 bg-violet-500/10 ring-1 ring-violet-400/40"
                    : "border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] hover:border-[color:var(--border-strong)]"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-medium text-[color:var(--foreground)]">
                    {campaign.crown_jewel_label || campaign.crown_jewel}
                  </span>
                  <span className="font-mono text-[11px] text-[color:var(--text-tertiary)]">
                    {campaign.path_count} path{campaign.path_count === 1 ? "" : "s"}
                  </span>
                </div>
                {campaign.top_path_summary ? (
                  <p className="mt-1 line-clamp-2 text-[11px] text-[color:var(--text-secondary)]">
                    {campaign.top_path_summary}
                  </p>
                ) : null}
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
