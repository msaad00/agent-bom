/**
 * Scan-pipeline branching DAG model + honesty reconciliation.
 *
 * The backend streams six linear stages (discovery → extraction → scanning →
 * enrichment → analysis → output). Rendered as a single row that reads as a
 * flat line, it hides the real shape of a scan: after extraction the work
 * fans out into parallel scanner domains (SCA / secrets / IaC / CIS / cloud)
 * that converge back into enrichment. This module turns the streamed steps
 * into that branching graph and derives per-domain finding counts so the
 * result chips reconcile with the domain lanes — a CIS run that is "32% pass"
 * is "68% fail", and those failures ARE findings, not "0 findings".
 *
 * Pure + framework-neutral (node.data is a plain record) so the branching
 * layout and reconciliation math are unit-testable without React Flow.
 */

import type { Edge, Node } from "@xyflow/react";
import type { StepEvent, StepStatus } from "@/lib/api";

export type PipelineNodeKind = "stage" | "scanner";

export type ScannerDomain = "sca" | "secrets" | "iac" | "cis" | "cloud";

export const SCANNER_DOMAINS: readonly ScannerDomain[] = ["sca", "secrets", "iac", "cis", "cloud"];

export interface PipelineGraphNodeSpec {
  id: string;
  label: string;
  kind: PipelineNodeKind;
  /** Backend step whose streamed status/timing this node reflects. */
  stepId: string;
  domain?: ScannerDomain;
  dependsOn: string[];
  description: string;
}

/**
 * The branching pipeline topology. Rank is implied by the dependency edges,
 * so the Sankey layout fans the scanner lanes out of `extraction` and back
 * into `enrichment` automatically — no hand-placed coordinates.
 */
export const PIPELINE_GRAPH: readonly PipelineGraphNodeSpec[] = [
  {
    id: "discovery",
    label: "Discovery",
    kind: "stage",
    stepId: "discovery",
    dependsOn: [],
    description: "Find agents, configs, and cloud accounts",
  },
  {
    id: "extraction",
    label: "Extraction",
    kind: "stage",
    stepId: "extraction",
    dependsOn: ["discovery"],
    description: "Resolve packages and assets to scan",
  },
  {
    id: "sca",
    label: "SCA · CVEs",
    kind: "scanner",
    domain: "sca",
    stepId: "scanning",
    dependsOn: ["extraction"],
    description: "Query vulnerability databases",
  },
  {
    id: "secrets",
    label: "Secrets",
    kind: "scanner",
    domain: "secrets",
    stepId: "scanning",
    dependsOn: ["extraction"],
    description: "Scan for exposed credentials",
  },
  {
    id: "iac",
    label: "IaC",
    kind: "scanner",
    domain: "iac",
    stepId: "scanning",
    dependsOn: ["extraction"],
    description: "Terraform / K8s misconfig checks",
  },
  {
    id: "cis",
    label: "CIS · CSPM",
    kind: "scanner",
    domain: "cis",
    stepId: "scanning",
    dependsOn: ["extraction"],
    description: "Benchmark cloud posture controls",
  },
  {
    id: "cloud",
    label: "Cloud posture",
    kind: "scanner",
    domain: "cloud",
    stepId: "scanning",
    dependsOn: ["extraction"],
    description: "Inventory + exposure evidence",
  },
  {
    id: "enrichment",
    label: "Enrichment",
    kind: "stage",
    stepId: "enrichment",
    dependsOn: [...SCANNER_DOMAINS],
    description: "NVD CVSS, EPSS, CISA KEV",
  },
  {
    id: "analysis",
    label: "Analysis",
    kind: "stage",
    stepId: "analysis",
    dependsOn: ["enrichment"],
    description: "Compute blast radius + reachability",
  },
  {
    id: "output",
    label: "Report",
    kind: "stage",
    stepId: "output",
    dependsOn: ["analysis"],
    description: "Publish findings, graph, compliance",
  },
];

const NODE_BY_ID = new Map(PIPELINE_GRAPH.map((spec) => [spec.id, spec]));

/** Backend step id a DAG node reflects (scanner lanes all map to `scanning`). */
export function backendStepForNode(nodeId: string): string {
  return NODE_BY_ID.get(nodeId)?.stepId ?? nodeId;
}

// ── Per-domain findings ──────────────────────────────────────────────────────

export interface CisSummary {
  passed: number | null;
  failed: number | null;
  total: number | null;
  passRate: number | null;
}

export interface DomainLaneData {
  /** Whether this scan actually exercised the domain. */
  ran: boolean;
  /** Findings this domain contributes to the reconciled total. */
  findings: number | null;
  /** Short label for the lane chip (e.g. "68 fail · 100 checks"). */
  detail?: string;
  /** True when the domain reports a summarised (synchronous) result with no streamed timing. */
  summarized?: boolean;
}

const EMPTY_LANE: DomainLaneData = { ran: false, findings: null };

/** Failed CIS checks — the honest "findings" count behind a pass rate. */
export function cisFailedCount(cis: CisSummary | null | undefined): number | null {
  if (!cis) return null;
  if (cis.failed != null && cis.failed >= 0) return cis.failed;
  if (cis.total != null && cis.passed != null) return Math.max(0, cis.total - cis.passed);
  if (cis.total != null && cis.passRate != null) {
    const rate = cis.passRate <= 1 ? cis.passRate : cis.passRate / 100;
    return Math.max(0, Math.round(cis.total * (1 - rate)));
  }
  return null;
}

function cisDetail(cis: CisSummary): string | undefined {
  const failed = cisFailedCount(cis);
  if (cis.total != null && failed != null) return `${failed} fail · ${cis.total} checks`;
  if (failed != null) return `${failed} fail`;
  return undefined;
}

export interface DeriveDomainLanesInput {
  /** SCA / CVE findings (e.g. scanning-step `vulnerabilities` stat or summary total). */
  vulnerabilities?: number | null;
  secrets?: number | null;
  iac?: number | null;
  cloudFindings?: number | null;
  cis?: CisSummary | null;
  /** True when the scan ran synchronously and carries no per-stage timing. */
  summarized?: boolean;
}

/**
 * Build the per-domain lane table. A domain only counts as "ran" when the
 * scan actually produced data for it — a repo SCA scan leaves the CIS/cloud
 * lanes as "not run" rather than fabricating a clean pass.
 */
export function deriveDomainLanes(
  input: DeriveDomainLanesInput,
): Record<ScannerDomain, DomainLaneData> {
  const summarized = input.summarized ?? false;
  const scalarLane = (value: number | null | undefined, noun: string): DomainLaneData => {
    if (value == null) return { ...EMPTY_LANE };
    return {
      ran: true,
      findings: value,
      detail: value === 0 ? "clean" : `${value} ${noun}`,
      summarized,
    };
  };

  const cisLane: DomainLaneData = (() => {
    if (!input.cis) return { ...EMPTY_LANE };
    const failed = cisFailedCount(input.cis);
    const lane: DomainLaneData = { ran: true, findings: failed, summarized };
    const detail = cisDetail(input.cis);
    if (detail !== undefined) lane.detail = detail;
    else if (failed === 0) lane.detail = "clean";
    return lane;
  })();

  return {
    sca: scalarLane(input.vulnerabilities, input.vulnerabilities === 1 ? "CVE" : "CVEs"),
    secrets: scalarLane(input.secrets, input.secrets === 1 ? "secret" : "secrets"),
    iac: scalarLane(input.iac, "misconfig"),
    cis: cisLane,
    cloud: scalarLane(input.cloudFindings, "exposure"),
  };
}

export interface ReconciledFindings {
  /** Total findings across every domain that ran (CIS fails included). */
  total: number;
  /** Number of scanner domains that actually ran. */
  domainsRun: number;
  byDomain: Record<ScannerDomain, number | null>;
}

/**
 * Reconcile the headline finding count with the domain lanes: CIS failures
 * count as findings, so a "0 vulnerabilities / 32% CIS pass" run reports the
 * 68 failing controls instead of a contradictory "0 findings".
 */
export function reconcileFindings(
  lanes: Record<ScannerDomain, DomainLaneData>,
): ReconciledFindings {
  let total = 0;
  let domainsRun = 0;
  const byDomain = {} as Record<ScannerDomain, number | null>;
  for (const domain of SCANNER_DOMAINS) {
    const lane = lanes[domain];
    byDomain[domain] = lane.ran ? lane.findings : null;
    if (lane.ran) {
      domainsRun += 1;
      if (lane.findings != null) total += lane.findings;
    }
  }
  return { total, domainsRun, byDomain };
}

// ── React Flow graph assembly ────────────────────────────────────────────────

/**
 * A scanner lane mirrors the single streamed `scanning` step, but a domain
 * the scan never touched should read as "skipped", not stuck "pending" or
 * falsely "done". Once scanning reaches a terminal state, lanes without data
 * collapse to skipped.
 */
export function laneStatus(scanStatus: StepStatus, ran: boolean): StepStatus {
  const terminal = scanStatus === "done" || scanStatus === "failed" || scanStatus === "skipped";
  if (terminal && !ran) return "skipped";
  return scanStatus;
}

const TERMINAL: ReadonlySet<StepStatus> = new Set<StepStatus>(["done", "failed", "skipped"]);

export interface BuildPipelineGraphInput {
  steps: Map<string, StepEvent>;
  lanes?: Record<ScannerDomain, DomainLaneData> | undefined;
  selectedNodeId?: string | null | undefined;
}

export interface BuildPipelineGraphResult {
  nodes: Node[];
  edges: Edge[];
}

function statusOf(
  spec: PipelineGraphNodeSpec,
  steps: Map<string, StepEvent>,
  lanes: Record<ScannerDomain, DomainLaneData> | undefined,
): StepStatus {
  const raw = (steps.get(spec.stepId)?.status ?? "pending") as StepStatus;
  if (spec.kind === "scanner" && spec.domain) {
    return laneStatus(raw, lanes?.[spec.domain]?.ran ?? false);
  }
  return raw;
}

/**
 * Assemble React Flow nodes + edges for the branching DAG. Positions are left
 * at the origin; the Sankey layout ranks nodes by the dependency edges, so
 * the fan-out/fan-in shape is fully derived from `dependsOn`.
 */
export function buildPipelineGraph(input: BuildPipelineGraphInput): BuildPipelineGraphResult {
  const { steps, lanes, selectedNodeId } = input;
  const statusById = new Map<string, StepStatus>();
  for (const spec of PIPELINE_GRAPH) statusById.set(spec.id, statusOf(spec, steps, lanes));

  const nodes: Node[] = PIPELINE_GRAPH.map((spec) => {
    const event = steps.get(spec.stepId);
    const status = statusById.get(spec.id) ?? "pending";
    const lane = spec.domain ? lanes?.[spec.domain] : undefined;
    return {
      id: spec.id,
      type: "pipelineStep",
      position: { x: 0, y: 0 },
      data: {
        nodeId: spec.id,
        stepId: spec.stepId,
        label: spec.label,
        description: spec.description,
        kind: spec.kind,
        domain: spec.domain,
        status,
        message: event?.message,
        // Only stages carry the streamed stat chips; scanner lanes show findings.
        stats: spec.kind === "stage" ? event?.stats : undefined,
        startedAt: event?.started_at,
        completedAt: event?.completed_at,
        progressPct: event?.progress_pct,
        findings: lane?.findings ?? null,
        ran: lane?.ran ?? spec.kind === "stage",
        detail: lane?.detail,
        summarized: lane?.summarized ?? false,
        selected: selectedNodeId === spec.id,
      },
    } satisfies Node;
  });

  const edges: Edge[] = [];
  for (const spec of PIPELINE_GRAPH) {
    for (const source of spec.dependsOn) {
      const sourceStatus = statusById.get(source);
      const targetStatus = statusById.get(spec.id);
      const active = sourceStatus === "running" || targetStatus === "running";
      const flowed = targetStatus === "done" && TERMINAL.has(sourceStatus ?? "pending");
      edges.push({
        id: `e-${source}-${spec.id}`,
        source,
        target: spec.id,
        type: "default",
        animated: active,
        style: {
          stroke:
            targetStatus === "failed"
              ? "var(--severity-critical)"
              : flowed
                ? "var(--status-success)"
                : "var(--border-strong)",
          strokeWidth: 1.75,
          opacity: targetStatus === "skipped" ? 0.4 : 1,
        },
      });
    }
  }

  return { nodes, edges };
}
