"use client";

import { useMemo, useState } from "react";
import { Check, Copy } from "lucide-react";

import {
  applySsoPreset,
  buildSsoEnvSnippet,
  ssoPresetsForProtocol,
  type SsoProtocol,
  type SsoProviderPreset,
} from "@/lib/sso-provider-presets";

function fieldTone(kind: SsoProviderPreset["fields"][number]["kind"]): string {
  switch (kind) {
    case "secret":
      return "border-amber-900/50 bg-amber-950/20 text-amber-200";
    case "tenant":
      return "border-sky-900/50 bg-sky-950/20 text-sky-200";
    case "config":
    default:
      return "border-[var(--border-subtle)] bg-[var(--surface)] text-[var(--text-secondary)]";
  }
}

function kindLabel(kind: SsoProviderPreset["fields"][number]["kind"]): string {
  switch (kind) {
    case "secret":
      return "You supply · secret";
    case "tenant":
      return "You supply";
    case "config":
    default:
      return "Prefilled";
  }
}

/**
 * Operator helper: pick an IdP preset and get the provider-specific OIDC/SAML
 * fields pre-filled with the issuer / discovery / endpoint shapes. Tenant and
 * secret values are never prefilled. Read-only guidance — SSO config is applied
 * via the AGENT_BOM_* environment (copy the generated block).
 */
export function SsoSetupPresets() {
  const [protocol, setProtocol] = useState<SsoProtocol>("oidc");
  const presets = ssoPresetsForProtocol(protocol);
  const [presetId, setPresetId] = useState<string>(presets[0]!.id);
  const [copied, setCopied] = useState(false);

  const preset = useMemo<SsoProviderPreset>(() => {
    return presets.find((p) => p.id === presetId) ?? presets[0]!;
  }, [presets, presetId]);

  const filled = useMemo(() => applySsoPreset(preset), [preset]);

  function selectProtocol(next: SsoProtocol) {
    setProtocol(next);
    setPresetId(ssoPresetsForProtocol(next)[0]!.id);
    setCopied(false);
  }

  async function copyEnv() {
    try {
      await navigator.clipboard.writeText(buildSsoEnvSnippet(preset));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/40 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-[0.18em] text-[var(--text-tertiary)]">SSO provider presets</p>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Pick your identity provider to pre-fill the issuer, discovery and endpoint shapes. You still supply your
            domain, client id and secret — secrets are never prefilled.
          </p>
        </div>
        <div className="inline-flex rounded-lg border border-[var(--border-subtle)] p-0.5" role="tablist" aria-label="SSO protocol">
          {(["oidc", "saml"] as const).map((value) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={protocol === value}
              onClick={() => selectProtocol(value)}
              className={`rounded-md px-3 py-1 text-xs font-semibold uppercase tracking-wide transition ${
                protocol === value
                  ? "bg-[var(--surface)] text-[var(--foreground)]"
                  : "text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
              }`}
            >
              {value}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {presets.map((option) => (
          <button
            key={option.id}
            type="button"
            aria-pressed={option.id === preset.id}
            onClick={() => {
              setPresetId(option.id);
              setCopied(false);
            }}
            className={`rounded-lg border px-3 py-1.5 text-sm transition ${
              option.id === preset.id
                ? "border-sky-500/70 bg-[var(--surface)] text-[var(--foreground)]"
                : "border-[var(--border-subtle)] bg-transparent text-[var(--text-secondary)] hover:text-[var(--foreground)]"
            }`}
          >
            {option.label}
          </button>
        ))}
      </div>

      <p className="mt-3 text-xs text-[var(--text-tertiary)]">{preset.tagline}</p>

      <div className="mt-3 overflow-x-auto">
        <div className="min-w-[36rem] space-y-1.5">
          {preset.fields.map((field) => (
            <div
              key={field.key}
              className={`flex items-start justify-between gap-3 rounded-lg border px-3 py-2 text-xs ${fieldTone(field.kind)}`}
            >
              <div className="min-w-0">
                <p className="font-mono text-[11px] text-[var(--text-tertiary)]">{field.envVar}</p>
                <p className="mt-0.5 font-mono text-[13px] break-all text-[var(--foreground)]">
                  {filled[field.key] ? filled[field.key] : <span className="text-[var(--text-tertiary)]">{field.placeholder}</span>}
                </p>
                {field.hint ? <p className="mt-0.5 text-[11px] text-[var(--text-tertiary)]">{field.hint}</p> : null}
              </div>
              <span className="shrink-0 rounded-full border border-[var(--border-subtle)] px-2 py-0.5 text-[10px] uppercase tracking-wide">
                {kindLabel(field.kind)}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between gap-3">
        <p className="text-[11px] text-[var(--text-tertiary)]">{preset.docsHint}</p>
        <button
          type="button"
          onClick={copyEnv}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] px-3 py-1.5 text-xs font-semibold text-[var(--text-secondary)] transition hover:text-[var(--foreground)]"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy env config"}
        </button>
      </div>
    </section>
  );
}
