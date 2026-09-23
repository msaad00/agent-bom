"use client";

import Link from "next/link";
import { useState } from "react";
import type { ExposurePath } from "@/lib/exposure-path";
import { GraphHopEvidenceInspector } from "@/components/graph-hop-evidence-inspector";

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
  const agents = [...new Set(path.hops.filter(hop => hop.role === "agent").map(hop => hop.label))];
  const resources = path.hops.filter(hop => hop.role === "environment" || hop.role === "cluster");
  const conditions = [
    ["Attack vector", path.evidence?.attackVector],
    ["Attack complexity", path.evidence?.attackComplexity],
    ["Privileges required", path.evidence?.privilegesRequired],
    ["User interaction", path.evidence?.userInteraction],
  ];
  const evidence = <GraphHopEvidenceInspector hops={path.hops} receipts={path.hopEvidence} />;
  return <section aria-label="Agent investigation questions" className="my-3 rounded-xl border border-outline bg-surface p-3 text-sm">
    <h3 className="font-semibold">Investigate this path</h3>
    <p className="mt-1 text-ink-secondary">Scope: this snapshot and selected path. Expand connections to inspect other agents, tools, services and resources.</p>
    <div role="group" aria-label="Investigation questions" className="my-3 flex flex-wrap gap-2">
      {QUESTIONS.map(item => <button key={item} type="button" aria-pressed={question === item} onClick={() => setQuestion(current => current === item ? null : item)}
        className={`min-h-11 rounded-lg border border-outline px-3 py-2 ${question === item ? "bg-emerald-600 text-white" : "text-foreground"}`}>{item}</button>)}
    </div>
    <section aria-label={question ?? "Choose an investigation question"} className="space-y-3">
      {question === "Reach & connections" && <>
        <p>{Math.max(0, path.hops.length - 1)} path hops · {receipts.length} matching receipts · {blocked.length} hops with recorded denial or blocking.</p>
        <p>Inspect each hop for identity, action, resource, direction, freshness and permission evidence. Graph connectivity alone does not establish effective access.</p>
        <button type="button" onClick={onConnections} className="min-h-11 rounded-lg border border-outline px-3 py-2">Explore incoming and outgoing connections</button>
        {evidence}
      </>}
      {question === "Assume compromise" && <>
        <label className="flex min-h-11 items-center gap-2"><input type="checkbox" checked={assumed} onChange={event => setAssumed(event.target.checked)} />Assume an attacker controls {agents[0] ?? "the path source"}</label>
        {assumed ? <>
          <p><strong>Scenario assumption only.</strong> Inspect the recorded path for candidate actions and stopping conditions. This does not establish a successful compromise.</p>
          <p>{blocked.length ? `${blocked.length} hops contain denial or blocking evidence. Do not assume downstream access through those hops.` : "No denial or blocking receipt is attached to this path; this is not proof that controls are absent."}</p>
          <p>Every subsequent action still needs applicable permission and vulnerability prerequisites. Missing receipts remain unknown.</p>
          {evidence}
        </> : <p>Select the assumption to examine this path as a conditional misuse scenario. No calls are executed or controls changed.</p>}
      </>}
      {question === "CVE conditions" && <>
        <p><strong>Local exploitability: {path.evidenceDimensions?.exploitability.verdict?.replaceAll("_", " ") ?? "not assessed"}.</strong> Advisory conditions describe the vulnerability, not whether this deployment satisfies them.</p>
        <dl className="grid gap-3 sm:grid-cols-2">{conditions.map(([label, value]) => <div key={label}><dt className="text-ink-secondary">{label}</dt><dd>{value || "Not recorded"}</dd></div>)}</dl>
        {path.evidence?.cvssVector && <p className="break-all font-mono text-xs">{path.evidence.cvssVector}</p>}
        <p>Next evidence: verify the deployed package version, vulnerable feature/configuration, reachable entry point, required privileges and effective mitigations. CVSS, EPSS and KEV alone cannot establish local exploitability.</p>
      </>}
      {question === "Potential impact" && <>
        <p>Recorded impact category: <strong>{path.evidenceDimensions?.impact.category ?? path.evidence?.impactCategory ?? "not recorded"}</strong>. This category is not an observed outcome.</p>
        {resources.length ? <><p>Resources on this path, subject to each hop's permissions and prerequisites:</p><ul className="list-disc pl-5">{resources.map(resource => <li key={resource.id}>{resource.label}</li>)}</ul></>
          : <p>No downstream data asset or environment is recorded on this path. Collect resource and authorization relationships before assigning a blast radius.</p>}
        <p>Next evidence: inspect the permitted action on each target and collect audit outcomes to distinguish attempted access, denial, failure and actual effects.</p>
      </>}
      {question === "Recorded activity" && <>
        <p>{observed.length} matching hop receipts record runtime activity; {blocked.length} hops record blocking or denial. An observed call does not establish vulnerable-code execution or successful access.</p>
        {!observed.length && <p>No runtime observation is attached to this path. Collect gateway or service audit events with stable agent, tool, target and event identities.</p>}
        {agents.map(agent => {
          const params = new URLSearchParams({ agent });
          if (scanId) params.set("scan", scanId);
          return <Link key={agent} href={`/traces?${params}`} className="mr-3 inline-block min-h-11 py-3 underline">Recorded activity for {agent}</Link>;
        })}
        {evidence}
      </>}
    </section>
  </section>;
}
