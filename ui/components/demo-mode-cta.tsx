"use client";

import { ArrowRight, Sparkles } from "lucide-react";

import { useDemoMode } from "@/hooks/use-demo-mode";
import { getSignInUrl } from "@/lib/runtime-config";

const CTA_LABEL = "Sign in";

function ctaHref(): string {
  return getSignInUrl();
}

/** @deprecated Page banner removed — demo is indicated by watermark + nav/sources CTA only. */
export function DemoModeBanner() {
  return null;
}

/** Compact nav-footer CTA for anonymous demo viewers. */
export function DemoNavSignIn({ collapsed = false }: { collapsed?: boolean }) {
  const { isDemoMode } = useDemoMode();

  if (!isDemoMode) return null;

  return (
    <a
      href={ctaHref()}
      data-testid="demo-nav-sign-in"
      className={`flex items-center gap-2 rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-[12px] font-medium text-[color:var(--foreground)] transition-colors hover:border-[color:var(--border-strong)] ${
        collapsed ? "justify-center px-2" : ""
      }`}
      title="Sign in to connect your cloud"
    >
      <Sparkles className="h-4 w-4 shrink-0" aria-hidden="true" />
      {!collapsed && (
        <>
          <span>Demo · Sign in</span>
          <ArrowRight className="ml-auto h-3.5 w-3.5" aria-hidden="true" />
        </>
      )}
    </a>
  );
}

/**
 * Slim connect funnel for read-only demo tenants. Replaces the full create-source
 * form on /sources instead of stacking on top of a page banner + watermark.
 */
export function DemoConnectCard() {
  const { isDemoMode } = useDemoMode();

  if (!isDemoMode) return null;

  return (
    <section
      data-testid="demo-connect-card"
      className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3"
    >
      <p className="text-sm text-[color:var(--text-secondary)]">
        <span className="font-medium text-[color:var(--foreground)]">Read-only demo.</span> Sign in to register cloud accounts and data sources.
      </p>
      <a
        href={ctaHref()}
        className="inline-flex shrink-0 items-center gap-2 rounded-md bg-emerald-500 px-3 py-1.5 text-sm font-medium text-black transition hover:bg-emerald-400"
      >
        {CTA_LABEL}
        <ArrowRight className="h-4 w-4" aria-hidden="true" />
      </a>
    </section>
  );
}
