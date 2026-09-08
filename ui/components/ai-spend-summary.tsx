import Link from "next/link";
import { ArrowRight } from "lucide-react";
import type { OverviewDomain } from "@/lib/api-types";

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

export function AiSpendSummary({ domain, loading }: { domain?: OverviewDomain | undefined; loading: boolean }) {
  const detail = domain?.detail;
  const available = detail?.available === true && detail.period === "all_recorded";
  const calls = available ? count(detail.total_calls) : null;
  const unpriced = available ? count(detail.unpriced_calls) : null;
  const spend = available && calls !== null && unpriced !== null && calls > unpriced ? count(detail.total_cost_usd) : null;
  const input = available ? count(detail.total_input_tokens) : null;
  const output = available ? count(detail.total_output_tokens) : null;
  const tokens = input !== null && output !== null ? input + output : null;
  const agents = available ? count(detail.agents) : null;
  const fmt = (n: number | null) => n === null ? "—" : n.toLocaleString("en-US");

  return (
    <section aria-label="AI spend & usage" className="mt-3 border-t border-outline pt-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-foreground">AI spend &amp; usage</h2>
        <Link href="/cost" className="inline-flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-300">View AI Spend <ArrowRight className="h-3 w-3" /></Link>
      </div>
      {loading && !domain ? <p role="status" className="mt-2 text-sm text-ink-secondary">Loading usage…</p> : !available ? (
        <p role="status" className="mt-2 text-sm text-ink-secondary">Usage scope unavailable. Open AI Spend for details.</p>
      ) : (
        <>
          <p className="mt-1 text-xs text-ink-secondary">All retained usage · Current tenant · Token estimates from ingested traces</p>
          <dl className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              ["Estimated spend", calls === 0 ? "No usage" : spend === null ? "Unavailable" : new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(spend)],
              ["Recorded tokens", fmt(tokens)],
              ["Recorded agents", fmt(agents)],
              ["Unpriced calls", fmt(unpriced)],
            ].map(([label, value]) => <div key={label}><dt className="text-xs text-ink-secondary">{label}</dt><dd className="mt-1 text-sm font-semibold tabular-nums text-foreground">{value}</dd></div>)}
          </dl>
          <p className="mt-2 text-xs text-ink-secondary">{fmt(calls)} recorded calls. Provider bills, subscriptions and infrastructure costs are not included.{unpriced ? " Unpriced calls leave spend incomplete." : ""}</p>
        </>
      )}
    </section>
  );
}
