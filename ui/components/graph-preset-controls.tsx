"use client";

import { useCallback, useEffect, useState } from "react";
import { Bookmark, Loader2, Trash2 } from "lucide-react";

import { api, type GraphFilterPreset } from "@/lib/api";

export type InvestigationPresetFilters = {
  severity: string | null;
  layer: string | null;
  evidenceTier: string | null;
  environment: string | null;
};

/**
 * Save / load / delete tenant graph filter presets via `/v1/graph/presets`.
 * Used on the security-graph investigation chrome (and reusable on lineage).
 */
export function GraphPresetControls({
  filters,
  onApply,
}: {
  filters: InvestigationPresetFilters;
  onApply: (filters: InvestigationPresetFilters) => void;
}) {
  const [presets, setPresets] = useState<GraphFilterPreset[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const listed = await api.listGraphPresets();
      setPresets(listed);
    } catch {
      setError("Could not load saved presets");
      setPresets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleSave() {
    const trimmed = name.trim();
    if (!trimmed) return;
    setSaving(true);
    setError(null);
    try {
      await api.saveGraphPreset({
        name: trimmed,
        description: "Investigation filter preset",
        filters: {
          severity: filters.severity,
          layer: filters.layer,
          evidence_tier: filters.evidenceTier,
          environment: filters.environment,
        },
      });
      setName("");
      await refresh();
    } catch {
      setError("Could not save preset");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(presetName: string) {
    setError(null);
    try {
      await api.deleteGraphPreset(presetName);
      await refresh();
    } catch {
      setError("Could not delete preset");
    }
  }

  function applyPreset(preset: GraphFilterPreset) {
    const raw = preset.filters ?? {};
    onApply({
      severity: typeof raw.severity === "string" ? raw.severity : null,
      layer: typeof raw.layer === "string" ? raw.layer : null,
      evidenceTier:
        typeof raw.evidence_tier === "string"
          ? raw.evidence_tier
          : typeof raw.evidenceTier === "string"
            ? raw.evidenceTier
            : null,
      environment: typeof raw.environment === "string" ? raw.environment : null,
    });
  }

  return (
    <div
      className="space-y-2 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-elevated)] p-3"
      data-testid="graph-preset-controls"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[color:var(--text-tertiary)]">
          Saved presets
        </p>
        {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin text-[color:var(--text-tertiary)]" /> : null}
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          type="text"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Preset name"
          aria-label="Preset name"
          className="min-w-[8rem] flex-1 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1.5 text-xs text-[color:var(--foreground)] outline-none focus:border-[color:var(--border-strong)]"
        />
        <button
          type="button"
          onClick={() => void handleSave()}
          disabled={saving || !name.trim()}
          className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-600/40 bg-emerald-500/10 px-2.5 py-1.5 text-xs font-medium text-emerald-800 disabled:opacity-50 dark:text-emerald-200"
        >
          <Bookmark className="h-3.5 w-3.5" />
          Save
        </button>
      </div>

      {presets.length > 0 ? (
        <ul className="flex flex-wrap gap-2">
          {presets.map((preset) => (
            <li key={preset.name} className="inline-flex items-center gap-1">
              <button
                type="button"
                onClick={() => applyPreset(preset)}
                className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface)] px-2.5 py-1 text-xs text-[color:var(--foreground)] transition hover:border-[color:var(--border-strong)]"
              >
                {preset.name}
              </button>
              <button
                type="button"
                aria-label={`Delete preset ${preset.name}`}
                onClick={() => void handleDelete(preset.name)}
                className="rounded-md border border-[color:var(--border-subtle)] p-1 text-[color:var(--text-tertiary)] transition hover:border-red-500/40 hover:text-red-400"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        !loading && (
          <p className="text-[11px] text-[color:var(--text-tertiary)]">
            No saved presets yet. Save the current severity / layer / evidence / environment chips.
          </p>
        )
      )}

      {error ? <p className="text-[11px] text-red-400">{error}</p> : null}
    </div>
  );
}
