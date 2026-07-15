import type { EnrichedVuln } from "@/lib/findings-view";

export interface WhyItMattersLink {
  href: string;
  label: string;
}

export interface WhyItMattersNarrative {
  headline: string;
  paragraphs: string[];
  /** Compliance control tags this finding maps to — rendered as scannable
   *  chips + a count rather than a run-on sentence. */
  complianceTags: string[];
  links: WhyItMattersLink[];
}

function reachSentence(vuln: EnrichedVuln): string | null {
  const band = vuln.effective_reach_band?.trim();
  if (!band) return null;
  const score =
    typeof vuln.effective_reach_score === "number"
      ? ` (score ${vuln.effective_reach_score.toFixed(0)})`
      : "";
  const hop =
    typeof vuln.graph_min_hop_distance === "number" && vuln.graph_min_hop_distance > 0
      ? ` with a ${vuln.graph_min_hop_distance}-hop graph path`
      : vuln.graph_reachable
        ? " with a confirmed graph path"
        : "";
  return `Reachability is ${band}${score}${hop}, so this finding is prioritized above static-only CVE noise.`;
}

function runtimeSentence(vuln: EnrichedVuln): string | null {
  const state = vuln.runtime_evidence?.state;
  if (!state || state === "static") return null;
  if (state === "blocked") {
    const count = vuln.runtime_evidence?.blocked_count;
    const suffix = typeof count === "number" && count > 0 ? ` (${count} blocked invocation${count === 1 ? "" : "s"})` : "";
    return `Runtime enforcement already blocked tool activity tied to this exposure${suffix}; use the trace explorer to prove the deny decision.`;
  }
  if (state === "observed") {
    const count = vuln.runtime_evidence?.observed_count;
    const suffix = typeof count === "number" && count > 0 ? ` (${count} observed call${count === 1 ? "" : "s"})` : "";
    return `Agents have invoked reachable tools on live paths${suffix}, so exploitability is not theoretical.`;
  }
  return `Runtime evidence is ${state}, which should be weighed alongside static reachability.`;
}

function exposureSentence(vuln: EnrichedVuln): string | null {
  const parts: string[] = [];
  if (vuln.agents.length > 0) {
    parts.push(`${vuln.agents.length} agent surface${vuln.agents.length === 1 ? "" : "s"}`);
  }
  if (vuln.exposed_credentials.length > 0) {
    parts.push(`${vuln.exposed_credentials.length} exposed credential name${vuln.exposed_credentials.length === 1 ? "" : "s"}`);
  }
  if (vuln.reachable_tools.length > 0) {
    parts.push(`${vuln.reachable_tools.length} confirmed tool${vuln.reachable_tools.length === 1 ? "" : "s"}`);
  }
  if (parts.length === 0) return null;
  let sentence = `Blast radius spans ${parts.join(", ")}.`;
  if (vuln.phantom_tools?.length) {
    sentence += ` ${vuln.phantom_tools.length} registry-only tool${vuln.phantom_tools.length === 1 ? " is" : "s are"} excluded from scoring.`;
  }
  return sentence;
}

export function buildWhyItMatters(vuln: EnrichedVuln): WhyItMattersNarrative | null {
  const paragraphs = [
    reachSentence(vuln),
    runtimeSentence(vuln),
    exposureSentence(vuln),
  ].filter((line): line is string => Boolean(line));

  // Compliance mapping is surfaced as scannable chips + a count (not a run-on
  // sentence), so it no longer gates the narrative on its own.
  const complianceTags = vuln.framework_tags?.filter(Boolean) ?? [];

  if (paragraphs.length === 0 && complianceTags.length === 0) {
    return null;
  }

  const links: WhyItMattersLink[] = [];
  if (vuln.graph_reachable || vuln.effective_reach_band) {
    links.push({ href: "/security-graph", label: "Open security graph" });
  }
  if (vuln.runtime_evidence?.state === "blocked") {
    links.push({ href: "/traces", label: "Open trace explorer" });
  } else if (vuln.runtime_evidence?.state && vuln.runtime_evidence.state !== "static") {
    links.push({ href: "/runtime", label: "Review runtime posture" });
  }
  if (vuln.framework_tags?.length) {
    links.push({ href: "/compliance", label: "View compliance evidence" });
  }

  const headline =
    vuln.severity === "critical" || vuln.severity === "high"
      ? "Prioritize remediation — reachable exposure with governance impact"
      : "Why this finding is ranked in your queue";

  return { headline, paragraphs, complianceTags, links };
}
