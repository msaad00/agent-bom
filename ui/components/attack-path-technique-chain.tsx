import { ChevronRight, Crosshair } from "lucide-react";

import type { AttackPath, TechniqueMapping } from "@/lib/graph-schema";

function catalogLabel(catalog: string): string {
  return catalog?.toLowerCase() === "atlas" ? "ATLAS" : "ATT&CK";
}

function confidenceLabel(confidence: number): string {
  const pct = Math.round(Math.max(0, Math.min(1, confidence)) * 100);
  return `${pct}%`;
}

/**
 * Renders the mapped MITRE ATT&CK / ATLAS technique sequence for a single
 * attack path as a compact, horizontally-scrollable kill-chain.
 *
 * Honesty (product §11): these are *potential* techniques inferred from the
 * path's observed graph evidence — never a claim of detected attacker
 * activity. A hop whose evidence maps to no technique is simply omitted (the
 * backend leaves it unmapped, fail-closed); the whole component renders
 * nothing when a path has no mappings, so no fabricated technique ever shows.
 */
export function AttackPathTechniqueChain({ path }: { path: AttackPath }) {
  const mappings: TechniqueMapping[] = path.technique_mappings ?? [];
  if (mappings.length === 0) {
    return null;
  }

  const ordered = [...mappings].sort((a, b) => a.hop_index - b.hop_index);

  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)]/70 p-3 lg:col-span-4">
      <div className="flex items-start gap-2">
        <Crosshair
          className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--text-tertiary)]"
          aria-hidden="true"
        />
        <div className="min-w-0">
          <p className="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
            Mapped ATT&amp;CK / ATLAS techniques
          </p>
          <p className="mt-1 text-[11px] leading-4 text-[var(--text-tertiary)]">
            Potential kill-chain techniques inferred from this path&apos;s graph
            evidence — not observed attacker activity.
          </p>
        </div>
      </div>

      <ol
        data-testid="technique-chain"
        className="mt-3 flex items-stretch gap-1.5 overflow-x-auto pb-1"
      >
        {ordered.map((m, i) => (
          <li
            key={`${m.hop_index}-${m.technique_id}-${i}`}
            className="flex items-stretch gap-1.5"
          >
            {i > 0 && (
              <div
                className="flex items-center text-[var(--text-tertiary)]"
                aria-hidden="true"
              >
                <ChevronRight className="h-3.5 w-3.5" />
              </div>
            )}
            <div
              title={
                m.provenance
                  ? `Evidence: ${m.provenance} · confidence ${confidenceLabel(m.confidence)}`
                  : `Confidence ${confidenceLabel(m.confidence)}`
              }
              className="flex min-w-[9.5rem] max-w-[15rem] shrink-0 flex-col gap-1 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-elevated)]/80 px-2.5 py-2"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[9px] uppercase tracking-[0.16em] text-[var(--text-tertiary)]">
                  Hop {m.hop_index + 1}
                </span>
                <span className="rounded border border-[var(--border-subtle)] bg-[var(--surface)]/80 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-[0.1em] text-[var(--text-secondary)]">
                  {catalogLabel(m.catalog)}
                </span>
              </div>
              <span
                data-testid="technique-id"
                className="font-mono text-[11px] font-semibold text-[var(--foreground)]"
              >
                {m.technique_id}
              </span>
              {m.technique_name && (
                <span className="text-[11px] leading-4 text-[var(--text-secondary)] [overflow-wrap:anywhere]">
                  {m.technique_name}
                </span>
              )}
              {m.tactics.length > 0 && (
                <div className="mt-0.5 flex flex-wrap gap-1">
                  {m.tactics.map((tactic) => (
                    <span
                      key={`${m.technique_id}-${tactic}`}
                      className="rounded bg-[var(--surface)]/80 px-1.5 py-0.5 text-[9px] text-[var(--text-tertiary)]"
                    >
                      {tactic}
                    </span>
                  ))}
                </div>
              )}
              <span className="mt-0.5 text-[9px] uppercase tracking-[0.14em] text-[var(--text-tertiary)]">
                Confidence {confidenceLabel(m.confidence)}
              </span>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
