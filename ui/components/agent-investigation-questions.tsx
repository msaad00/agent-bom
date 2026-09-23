"use client";

import Link from "next/link";
import { useState } from "react";
import type { ExposurePath } from "@/lib/exposure-path";
import { GraphHopEvidenceInspector } from "@/components/graph-hop-evidence-inspector";

const SHORT_LABELS = ["Connections", "Compromise", "CVE conditions", "Impact", "Activity"];
const QUESTIONS = ["Reach & connections", "Assume compromise", "CVE conditions", "Potential impact", "Recorded activity"] as const;

/** Reads the selected path's receipts; never turns a scenario into an observation. */
export function AgentInvestigationQuestions({ path, scanId, onConnections }: {
  path: ExposurePath; scanId?: string | undefined; onConnections: () => void;
}) {
  const [question, setQuestion] = useState<typeof QUESTIONS[number] | null>(null);
  const [assumed, setAssumed] = useState(false);
  const receipts = path.hops.slice(1).flatMap((target, index) => {
    const receipt = path.hopEvidence?.[index];
    if (!receipt) return [];
    return receipt.source_node_id === path.hops[index]?.id && receipt.target_node_id === target.id ? [receipt] : [];
  });
  const blocked = receipts.filter(receipt => receipt.runtime_observed_state === "blocked" || receipt.runtime_outcome === "blocked"
    || receipt.authority?.decisions?.some(decision => decision.decision === "explicit_deny" || decision.decision === "implicit_deny"));
  const observed = receipts.filter(receipt => receipt.runtime_observed_state === "observed" || receipt.runtime_observed_state === "blocked");
  const agents = [...new Set(path.hops.filter(hop => hop.entityType === "agent").flatMap(hop => hop.rawLabel ? [hop.rawLabel] : []))];
  const scenarioStart = path.hops.findIndex(hop => hop.entityType === "agent");
  const scenarioHops = scenarioStart >= 0 ? path.hops.slice(scenarioStart) : [];
  const scenarioBlocked = blocked.filter(receipt => scenarioHops.some(hop => hop.id === receipt.source_node_id));
  const resources = path.hops.filter(hop => ["environment", "cluster", "data_store", "dataset", "resource", "cloud_resource"].includes(hop.entityType ?? ""));
  const conditions = [
    ["Attack vector", path.evidence?.attackVector],
    ["Attack complexity", path.evidence?.attackComplexity],
    ["Privileges required", path.evidence?.privilegesRequired],
    ["User interaction", path.evidence?.userInteraction],
  ];
  const evidence = <GraphHopEvidenceInspector hops={path.hops} receipts={path.hopEvidence} />;
  return <section aria-label="Agent investigation questions" className="my-3 rounded-xl border border-outline bg-surface p-3 text-[15px]">
    <details><summary className="cursor-pointer py-2 font-semibold">Investigate this path</summary>
    <p className="mt-1 text-ink-secondary">Selected path · snapshot evidence.</p>
    <div role="group" aria-label="Investigation questions" className="my-3 grid grid-cols-2 gap-2">
      {QUESTIONS.map((item, index) => <button key={item} aria-label={item} type="button" aria-pressed={question === item} onClick={() => setQuestion(current => current === item ? null : item)}
        className={`min-h-11 rounded-lg border border-outline px-3 py-2 ${question === item ? "bg-emerald-600 text-white" : "text-foreground"}`}>{SHORT_LABELS[index]}</button>)}
    </div>
    <section aria-label={question ?? "Choose an investigation question"} className="space-y-3">
      {question === "Reach & connections" && <>
        <p>{Math.max(0, path.hops.length - 1)} path hops · {receipts.length} matching receipts · {blocked.length} hops with recorded denial or blocking.</p>
        <p>Inspect each hop for identity, action, resource, direction, freshness and permission evidence. Graph connectivity alone does not establish effective access.</p>
        <button type="button" onClick={onConnections} className="min-h-11 rounded-lg border border-outline px-3 py-2">Explore incoming and outgoing connections</button>
        {evidence}
      </>}
      {question === "Assume compromise" && <>
        {scenarioStart < 0 ? <p>No canonical agent is recorded on this path. Collect agent identity before assigning a compromise scenario.</p> : <label className="flex min-h-11 items-center gap-2"><input type="checkbox" checked={assumed} onChange={event => setAssumed(event.target.checked)} />Assume an attacker controls {path.hops[scenarioStart]?.label}</label>}
        {assumed && scenarioStart >= 0 ? <>
          <p><strong>Scenario assumption only.</strong> Inspect the recorded path for candidate actions and stopping conditions. This does not establish a successful compromise.</p>
          <p>{scenarioBlocked.length ? `${scenarioBlocked.length} hops contain denial or blocking evidence. Do not assume downstream access through those hops.` : "No denial or blocking receipt is attached to this path; this is not proof that controls are absent."}</p>
          <p>Every subsequent action still needs applicable permission and vulnerability prerequisites. Missing receipts remain unknown.</p>
          <GraphHopEvidenceInspector hops={scenarioHops} receipts={path.hopEvidence?.slice(scenarioStart)} />
        </> : <p>Select the assumption to examine this path as a conditional misuse scenario. No calls are executed or controls changed.</p>}
      </>}
      {question === "CVE conditions" && <>
        <p><strong>Local exploitability: {path.evidenceDimensions?.exploitability.verdict?.replaceAll("_", " ") ?? "not assessed"}.</strong> Advisory conditions describe the vulnerability, not whether this deployment satisfies them.</p>
        <dl className="grid gap-3 sm:grid-cols-2">{conditions.map(([label, value]) => <div key={label}><dt className="text-ink-secondary">{label}</dt><dd>{value || "Not recorded"}</dd></div>)}</dl>
        {path.evidence?.cvssVector && <p className="break-all font-mono text-xs">{path.evidence.cvssVector}</p>}
        <details><summary className="cursor-pointer py-2 font-medium">Evidence to collect next</summary><p>Verify the deployed package version, vulnerable feature/configuration, reachable entry point, required privileges and effective mitigations. CVSS, EPSS and KEV alone cannot establish local exploitability.</p></details>
      </>}
      {question === "Potential impact" && <>
        <p>Recorded impact category: <strong>{path.evidenceDimensions?.impact.category ?? path.evidence?.impactCategory ?? "not recorded"}</strong>. This category is not an observed outcome.</p>
        {resources.length ? <><p>Resources on this path, subject to each hop's permissions and prerequisites:</p><ul className="list-disc pl-5">{resources.map(resource => <li key={resource.id}>{resource.label}</li>)}</ul></>
          : <p>No downstream data asset or environment is identified by the available node types on this path. Collect resource and authorization relationships before assigning a blast radius.</p>}
        <p>Next evidence: inspect the permitted action on each target and collect audit outcomes to distinguish attempted access, denial, failure and actual effects.</p>
      </>}
      {question === "Recorded activity" && <>
        <p>{observed.length} matching hop receipts record runtime activity; {blocked.length} hops record blocking or denial. An observed call does not establish vulnerable-code execution or successful access.</p>
        {!observed.length && <p>No runtime observation is attached to this path. Collect gateway or service audit events with stable agent, tool, target and event identities.</p>}
        {!agents.length && <p>A recorded agent name is unavailable; an activity filter cannot be established from display labels.</p>}
        {!!agents.length && <p>Activity is filtered by the recorded agent name. Shared names may include other agents; use exact event references to correlate a hop.</p>}
        {agents.map(agent => {
          const params = new URLSearchParams({ agent });
          if (scanId) params.set("scan", scanId);
          return <Link key={agent} href={`/traces?${params}`} className="mr-3 inline-block min-h-11 py-3 underline">Recorded activity for {agent}</Link>;
        })}
        {evidence}
      </>}
    </section>
    </details>
  </section>;
}
