import Link from "next/link";
import { version } from "../package.json";

type PersonaStart = {
  label: string;
  persona: string;
  command: string;
  artifact: string;
  href: string;
};

const STARTS: PersonaStart[] = [
  {
    label: "CLI scan",
    persona: "Developer / agent builder",
    command: "agent-bom scan .",
    artifact: "Inventory, prioritized findings, and exportable evidence",
    href: "/scan",
  },
  {
    label: "Docker scan",
    persona: "Developer / evaluator",
    command: `docker run --rm agentbom/agent-bom:${version} scan --demo --offline`,
    artifact: "Synthetic inventory and findings; exit 1 is the expected security verdict",
    href: "/scan",
  },
  {
    label: "GitHub Action",
    persona: "AppSec / SecOps",
    command: `uses: koda-ai-studio/agent-bom@v${version}`,
    artifact: "SARIF, pull-request summary, and policy exit code",
    href: "/findings",
  },
  {
    label: "Control plane",
    persona: "Platform operator",
    command: "agent-bom serve --host 127.0.0.1",
    artifact: "Centralized fleet, findings, graph, and audit evidence",
    href: "/connections",
  },
  {
    label: "Compliance evidence",
    persona: "GRC / audit",
    command: "agent-bom scan . --compliance",
    artifact: "Control mappings with assessment scope; review missing evidence before an audit",
    href: "/compliance",
  },
  {
    label: "Runtime enforcement",
    persona: "Security / platform",
    command: "agent-bom gateway serve --from-control-plane http://127.0.0.1:8422",
    artifact: "Allow, warn, block, and auditable tool-call decisions",
    href: "/runtime",
  },
];

export function PersonaStartRoutes() {
  return (
    <section
      role="region"
      aria-label="Start by workflow"
      className="rounded-2xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] elev-1"
    >
      <details className="group">
        <summary className="flex cursor-pointer list-none items-start justify-between gap-4 p-5 [&::-webkit-details-marker]:hidden">
          <span>
            <span className="block text-sm font-semibold text-[color:var(--foreground)]">Start with the workflow you already use</span>
            <span className="mt-1 block text-xs text-[color:var(--text-tertiary)]">First command → artifact → existing product surface. Local scan is one entry point, not the product boundary.</span>
          </span>
          <span className="shrink-0 text-[10px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)] group-open:hidden">Show 6 starts</span>
          <span className="hidden shrink-0 text-[10px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)] group-open:inline">Hide starts</span>
        </summary>
        <div className="grid gap-3 border-t border-[color:var(--border-subtle)] p-5 md:grid-cols-2 xl:grid-cols-3">
          {STARTS.map((start) => (
            <article key={start.label} className="min-w-0 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] p-4">
              <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[color:var(--text-tertiary)]">{start.persona}</p>
              <h3 className="mt-1 text-sm font-semibold text-[color:var(--foreground)]">{start.label}</h3>
              <code className="mt-3 block overflow-x-auto rounded-md bg-[color:var(--background)] px-2.5 py-2 text-[11px] text-emerald-700 dark:text-emerald-200">{start.command}</code>
              <p className="mt-3 text-xs leading-5 text-[color:var(--text-secondary)]">{start.artifact}</p>
              <Link href={start.href} className="mt-3 inline-flex text-xs font-medium text-emerald-700 hover:underline dark:text-emerald-300">
                Continue in product
              </Link>
            </article>
          ))}
        </div>
      </details>
    </section>
  );
}
