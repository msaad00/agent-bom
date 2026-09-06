import { buildFindingInvestigationHref } from "@/lib/finding-investigation-href";
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
        ? " with a reported graph path"
        : "";
  return `Reported reachability is ${band}${score}${hop}. Inspect the path evidence before concluding that the finding is exploitable.`;
}

function runtimeSentence(vuln: EnrichedVuln): string | null {
  const state = vuln.runtime_evidence?.state;
  if (!state || state === "static") return null;
  if (state === "blocked") {
    const count = vuln.runtime_evidence?.blocked_count;
    const suffix = typeof count === "number" && count > 0 ? ` (${count} blocked invocation${count === 1 ? "" : "s"})` : "";
    return `Runtime enforcement recorded blocked tool activity${suffix}; remediation still needs verification. Review the trace for the deny decision.`;
  }
  if (state === "observed") {
    const count = vuln.runtime_evidence?.observed_count;
    const suffix = typeof count === "number" && count > 0 ? ` (${count} observed call${count === 1 ? "" : "s"})` : "";
    return `Runtime tool activity was observed${suffix}. Activity alone does not prove exploitation or a complete attack path.`;
  }
  return `Runtime evidence is ${state}, which should be weighed alongside static reachability.`;
}

function exposureSentence(vuln: EnrichedVuln): string | null {
  const parts: string[] = [];
  if (vuln.agents.length > 0) {
    parts.push(`${vuln.agents.length} agent surface${vuln.agents.length === 1 ? "" : "s"}`);
  }
  if (vuln.exposed_credentials.length > 0) {
    parts.push(`${vuln.exposed_credentials.length} credential reference${vuln.exposed_credentials.length === 1 ? "" : "s"}`);
  }
  if (vuln.reachable_tools.length > 0) {
    parts.push(`${vuln.reachable_tools.length} linked tool${vuln.reachable_tools.length === 1 ? "" : "s"}`);
  }
  if (parts.length === 0) return null;
  let sentence = `Reported scope includes ${parts.join(", ")}.`;
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
  if (vuln.graph_reachable || vuln.effective_reach_band || vuln.node_id || vuln.finding_node_id) {
    links.push({ href: buildFindingInvestigationHref(vuln), label: "Open investigation" });
  }
  if (vuln.runtime_evidence?.state === "blocked") {
    links.push({ href: "/traces", label: "Open trace explorer" });
  } else if (vuln.runtime_evidence?.state && vuln.runtime_evidence.state !== "static") {
    links.push({ href: "/runtime", label: "Review runtime posture" });
  }
  if (vuln.framework_tags?.length) {
    links.push({ href: "/compliance", label: "View compliance evidence" });
  }

  const headline = "Reported scope and activity";

  return { headline, paragraphs, complianceTags, links };
}
