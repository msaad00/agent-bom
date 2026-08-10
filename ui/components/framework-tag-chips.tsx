"use client";

import { useState } from "react";

/**
 * A finding's framework tags, bounded.
 *
 * `tag_blast_radius` returns **36** ATLAS techniques for a critical CVE on an
 * agent path with exposed credentials and an execute-capable tool, and can emit
 * 45. Every surface rendered the list unbounded with each technique's full name
 * inline, so one finding buried the evidence under it.
 *
 * The breadth is not the defect — an applicability overlay (#4709) genuinely
 * does put that many techniques in play — so this shows the first few, states
 * how many are hidden, and lets the reader open the rest. The count is never
 * silently cut: a reader can always tell the difference between "six
 * techniques" and "six of thirty-six".
 */

const DEFAULT_VISIBLE = 6;

/**
 * Tones are spelled out as whole class strings on purpose. The previous
 * `bg-${color}-950` form in `attack-flow.tsx` cannot be seen by Tailwind's
 * static extractor, so those classes were never generated and the chips
 * rendered with no background or border at all.
 */
type Tone = "owasp" | "mcp" | "atlas";

const TONE_CLASS: Record<Tone, string> = {
  owasp: "bg-purple-950 border-purple-800 text-purple-400",
  mcp: "bg-amber-950 border-amber-800 text-amber-400",
  atlas: "bg-cyan-950 border-cyan-800 text-cyan-400",
};

const TONE_NAME_CLASS: Record<Tone, string> = {
  owasp: "text-purple-600",
  mcp: "text-amber-600",
  atlas: "text-cyan-600",
};

export function FrameworkTagChips({
  tags,
  catalog,
  tone,
  showNames = false,
  visible = DEFAULT_VISIBLE,
}: {
  tags: string[] | undefined;
  catalog: Record<string, string>;
  tone: Tone;
  /** Render the technique name beside its id. Off in dense rows. */
  showNames?: boolean;
  visible?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const all = tags ?? [];
  if (all.length === 0) return null;

  const shown = expanded ? all : all.slice(0, visible);
  const hidden = all.length - shown.length;

  return (
    <>
      {shown.map((tag) => (
        <span
          key={tag}
          data-testid="framework-tag-chip"
          title={catalog[tag] ?? tag}
          className={`text-xs font-mono ${TONE_CLASS[tone]} border rounded px-1.5 py-0.5 cursor-help`}
        >
          {tag}
          {showNames && catalog[tag] ? (
            <span className={`ml-1 ${TONE_NAME_CLASS[tone]} font-sans`}>{catalog[tag]}</span>
          ) : null}
        </span>
      ))}
      {hidden > 0 || expanded ? (
        <button
          type="button"
          onClick={() => setExpanded((open) => !open)}
          className="text-xs text-[color:var(--text-tertiary)] underline decoration-dotted underline-offset-2 hover:text-[color:var(--text-secondary)]"
        >
          {expanded ? "show fewer" : `+${hidden} more`}
        </button>
      ) : null}
    </>
  );
}

export default FrameworkTagChips;
