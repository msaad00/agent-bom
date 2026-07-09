"use client";

import { ArrowRight, Cloud, Sparkles } from "lucide-react";

import { useDemoMode } from "@/hooks/use-demo-mode";
import { getSignInUrl } from "@/lib/runtime-config";

const CTA_LABEL = "Sign in / Get started";

function ctaHref(): string {
  return getSignInUrl();
}

/**
 * Slim, theme-aware strip shown at the top of app surfaces (dashboard, connect,
 * everywhere the shell renders) when the platform is running in public-demo
 * mode. Explains the sample-data context and funnels the anonymous viewer to
 * the sign-in / get-started flow. Renders nothing outside demo mode.
 */
export function DemoModeBanner() {
  const { isDemoMode } = useDemoMode();

  if (!isDemoMode) return null;

  return (
    <div
      data-testid="demo-mode-banner"
      className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-emerald-500/30 bg-[linear-gradient(135deg,var(--surface),var(--surface-elevated))] px-4 py-3 shadow-sm shadow-black/5"
    >
      <div className="flex items-center gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md border border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
          <Sparkles className="h-4 w-4" aria-hidden="true" />
        </span>
        <p className="text-sm leading-5 text-[color:var(--text-secondary)]">
          <span className="font-semibold text-[color:var(--foreground)]">You&rsquo;re exploring a live demo with sample data.</span>{" "}
          Connect your own cloud to scan your real estate.
        </p>
      </div>
      <a
        href={ctaHref()}
        className="inline-flex shrink-0 items-center gap-2 rounded-md bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400"
      >
        {CTA_LABEL}
        <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </a>
    </div>
  );
}

/**
 * Card variant for the connect / sources surface. The anonymous demo viewer is
 * read-only and cannot register a real source, so instead of showing a
 * forbidden "Create source" action we present the sign-in funnel. Renders
 * nothing outside demo mode (the normal authenticated form stays in place).
 */
export function DemoConnectCard() {
  const { isDemoMode } = useDemoMode();

  if (!isDemoMode) return null;

  return (
    <section
      data-testid="demo-connect-card"
      className="rounded-lg border border-emerald-500/30 bg-[linear-gradient(135deg,var(--surface),var(--surface-elevated))] p-5 shadow-sm shadow-black/5"
    >
      <div className="flex items-start gap-3">
        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
          <Cloud className="h-5 w-5" aria-hidden="true" />
        </span>
        <div>
          <h2 className="text-base font-semibold text-[color:var(--foreground)]">Connect your cloud</h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-[color:var(--text-secondary)]">
            This is a read-only demo estate with sample data, so connecting a real source is disabled here.
            Sign in to the full product to register your own cloud accounts, registries, and warehouses.
          </p>
        </div>
      </div>
      <a
        href={ctaHref()}
        className="mt-4 inline-flex items-center gap-2 rounded-md bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400"
      >
        Connect your cloud — {CTA_LABEL}
        <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </a>
    </section>
  );
}
