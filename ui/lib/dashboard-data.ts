import type { ElementType } from "react";
import {
  Container,
  ExternalLink,
  FileText,
  Layers,
  Server,
} from "lucide-react";

import type { Agent, BlastRadius, ScanJob, ScanResult } from "@/lib/api";
import type {
  EpssDataPoint,
  EpssVsCvssPoint,
  TrendDataPoint,
} from "@/components/charts";
import type { ExposurePathView } from "@/components/overview-cockpit";
import { buildSecurityGraphHref } from "@/lib/attack-paths";
import { severityRank } from "@/lib/severity";

// ─── Shared dashboard aggregation ───────────────────────────────────────────
// Pure data helpers extracted from app/page.tsx so both the slim dashboard shell
// and the lazily-loaded analytics surface can share them without dragging the
// heavy chart/table components into the home route's first-paint bundle.

export interface AggregatedPackage {
  name: string;
  version: string;
  ecosystem: string;
  vulnCount: number;
  critCount: number;
  highCount: number;
  agents: string[];
}

export function aggregatePackages(jobs: ScanJob[]): AggregatedPackage[] {
  const pkgMap = new Map<string, AggregatedPackage>();
  for (const job of jobs) {
    if (job.status !== "done" || !job.result) continue;
    const result = job.result as ScanResult;
    for (const agent of result.agents) {
      for (const srv of agent.mcp_servers) {
        for (const pkg of srv.packages) {
          const key = `${pkg.name}@${pkg.version}`;
          const existing = pkgMap.get(key);
          const vulns = pkg.vulnerabilities ?? [];
          const crit = vulns.filter((v) => v.severity === "critical").length;
          const high = vulns.filter((v) => v.severity === "high").length;
          if (existing) {
            existing.vulnCount = Math.max(existing.vulnCount, vulns.length);
            existing.critCount = Math.max(existing.critCount, crit);
            existing.highCount = Math.max(existing.highCount, high);
            if (!existing.agents.includes(agent.name)) existing.agents.push(agent.name);
          } else {
            pkgMap.set(key, {
              name: pkg.name,
              version: pkg.version,
              ecosystem: pkg.ecosystem,
              vulnCount: vulns.length,
              critCount: crit,
              highCount: high,
              agents: [agent.name],
            });
          }
        }
      }
    }
  }
  return Array.from(pkgMap.values())
    .filter((p) => p.vulnCount > 0)
    .sort((a, b) => b.critCount - a.critCount || b.highCount - a.highCount || b.vulnCount - a.vulnCount);
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export function aggregateSeverity(allBlast: BlastRadius[]): SeverityCounts {
  const c = { critical: 0, high: 0, medium: 0, low: 0, total: allBlast.length };
  for (const b of allBlast) {
    const s = b.severity?.toLowerCase();
    if (s === "critical") c.critical++;
    else if (s === "high") c.high++;
    else if (s === "medium") c.medium++;
    else if (s === "low") c.low++;
  }
  return c;
}

export interface ScanSource {
  label: string;
  icon: ElementType;
  count: number;
  vulns: number;
  critical: number;
}

const SOURCE_META: Record<string, { label: string; icon: ElementType }> = {
  agent_discovery: { label: "MCP Agents", icon: Server },
  image: { label: "Container Images", icon: Container },
  k8s: { label: "Kubernetes", icon: Layers },
  sbom: { label: "SBOM Imports", icon: FileText },
  filesystem: { label: "Filesystem", icon: FileText },
  terraform: { label: "Terraform", icon: Layers },
  github_actions: { label: "GitHub Actions", icon: Layers },
  browser_extensions: { label: "Browser Extensions", icon: ExternalLink },
  jupyter: { label: "Jupyter Notebooks", icon: FileText },
  gpu_infra: { label: "GPU Infrastructure", icon: Server },
};

export function aggregateSources(jobs: ScanJob[]): ScanSource[] {
  const srcMap = new Map<string, ScanSource>();

  for (const job of jobs) {
    if (job.status !== "done") continue;
    const result = job.result as ScanResult | undefined;
    const blast = result?.blast_radius ?? [];
    // Prefer scan_sources from result (auto-detected), fall back to request inference
    const sources = result?.scan_sources ?? [];

    if (sources.length > 0) {
      for (const src of sources) {
        const meta = SOURCE_META[src] ?? { label: src, icon: FileText };
        const existing = srcMap.get(src);
        if (existing) {
          existing.count++;
          existing.vulns += blast.length;
          existing.critical += blast.filter((b) => b.severity === "critical").length;
        } else {
          srcMap.set(src, {
            label: meta.label,
            icon: meta.icon,
            count: 1,
            vulns: blast.length,
            critical: blast.filter((b) => b.severity === "critical").length,
          });
        }
      }
    } else {
      // Legacy fallback: infer from request
      const req = job.request;
      if (req.images && req.images.length > 0) {
        const e = srcMap.get("image") ?? { label: "Container Images", icon: Container, count: 0, vulns: 0, critical: 0 };
        e.count += req.images.length;
        e.vulns += blast.length;
        e.critical += blast.filter((b) => b.severity === "critical").length;
        srcMap.set("image", e);
      } else {
        const e = srcMap.get("agent_discovery") ?? { label: "MCP Agents", icon: Server, count: 0, vulns: 0, critical: 0 };
        e.count++;
        e.vulns += blast.length;
        e.critical += blast.filter((b) => b.severity === "critical").length;
        srcMap.set("agent_discovery", e);
      }
    }
  }
  return Array.from(srcMap.values());
}

export function aggregateTrend(jobs: ScanJob[]): TrendDataPoint[] {
  const done = jobs
    .filter((j) => j.status === "done" && j.result)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));
  return done?.map((j) => {
    const blast = (j.result as ScanResult)?.blast_radius ?? [];
    const sev = aggregateSeverity(blast);
    const d = new Date(j.created_at);
    return {
      label: `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`,
      critical: sev.critical,
      high: sev.high,
      medium: sev.medium,
      low: sev.low,
    };
  });
}

export function aggregateEpss(allBlast: BlastRadius[]): EpssDataPoint[] {
  const buckets = [
    { range: "0-10%", min: 0, max: 0.1, count: 0 },
    { range: "10-30%", min: 0.1, max: 0.3, count: 0 },
    { range: "30-50%", min: 0.3, max: 0.5, count: 0 },
    { range: "50-70%", min: 0.5, max: 0.7, count: 0 },
    { range: "70-90%", min: 0.7, max: 0.9, count: 0 },
    { range: "90-100%", min: 0.9, max: 1.01, count: 0 },
  ];
  for (const b of allBlast) {
    if (b.epss_score == null) continue;
    for (const bucket of buckets) {
      if (b.epss_score >= bucket.min && b.epss_score < bucket.max) {
        bucket.count++;
        break;
      }
    }
  }
  return buckets?.map(({ range, count }) => ({ range, count }));
}

export function aggregateEpssVsCvss(allBlast: BlastRadius[]): EpssVsCvssPoint[] {
  return allBlast
    .filter((b) => b.cvss_score != null && b.epss_score != null)
    .map((b) => ({
      cve: b.vulnerability_id,
      cvss: b.cvss_score!,
      epss: b.epss_score!,
      blast: b.risk_score ?? b.blast_score,
      severity: b.severity?.toLowerCase() ?? "low",
      kev: !!(b.is_kev ?? b.cisa_kev),
      package: b.package,
    }));
}

// Compound issue: a finding that meets 2+ independent risk signals simultaneously.
// Each rule returns a subset of blast radius entries.
export interface CompoundIssue {
  id: string;
  title: string;
  description: string;
  count: number;
  severity: "critical" | "high";
  findings: BlastRadius[];
  filter: string; // URL param for /findings deep-link
}

export function blastTools(blast: BlastRadius): string[] {
  return blast.exposed_tools ?? blast.reachable_tools ?? [];
}

export function blastCredentials(blast: BlastRadius): string[] {
  return blast.exposed_credentials ?? [];
}

export function blastAgents(blast: BlastRadius): string[] {
  return blast.affected_agents ?? [];
}

/**
 * Build the exec→graph exposure-path row for a finding. Threads the finding's
 * own `scanId` into the security-graph drill so the drill lands on the scan
 * that produced the finding — not whichever scan happens to be latest (#3966).
 * `index` disambiguates the key within a shortlist; omit it for a single row.
 */
export function buildExposurePathView(
  blast: BlastRadius,
  scanId?: string,
  index?: number,
): ExposurePathView {
  const agents = blastAgents(blast);
  const credentials = blastCredentials(blast);
  const nodes: ExposurePathView["nodes"] = [
    { type: "cve", label: blast.vulnerability_id, severity: blast.severity?.toLowerCase() },
  ];
  if (blast.package) nodes.push({ type: "package", label: blast.package });
  if (blast.affected_servers && blast.affected_servers.length > 0) {
    nodes.push({ type: "server", label: blast.affected_servers[0]! });
  }
  if (agents.length > 0) nodes.push({ type: "agent", label: agents[0]! });
  if (credentials.length > 0) nodes.push({ type: "credential", label: credentials[0]! });
  const baseKey = `${blast.vulnerability_id}:${blast.package ?? "unknown"}`;
  return {
    key: index === undefined ? baseKey : `${baseKey}:${index}`,
    nodes,
    riskScore: blast.risk_score ?? blast.blast_score / 10,
    href: buildSecurityGraphHref({
      scanId,
      cve: blast.vulnerability_id,
      packageName: blast.package,
      agentName: agents[0],
    }),
  };
}

export function aggregateCompoundIssues(allBlast: BlastRadius[]): CompoundIssue[] {
  const issues: CompoundIssue[] = [];

  // 1. CISA KEV + reachable tool exposure
  const kevReachable = allBlast.filter(
    (b) => (b.is_kev ?? b.cisa_kev) && blastTools(b).length > 0
  );
  if (kevReachable.length > 0) {
    issues.push({
      id: "kev-reachable",
      title: "Actively Exploited + Tool Reachability",
      description:
        "Known-exploited vulnerabilities (CISA KEV) in packages reachable by MCP tools — immediate patching required.",
      count: kevReachable.length,
      severity: "critical",
      findings: kevReachable.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "kev=true",
    });
  }

  // 2. CISA KEV + credential exposure
  const kevCredential = allBlast.filter(
    (b) => (b.is_kev ?? b.cisa_kev) && blastCredentials(b).length > 0
  );
  if (kevCredential.length > 0) {
    issues.push({
      id: "kev-credential",
      title: "Actively Exploited + Credential Exposure",
      description:
        "Known-exploited CVEs co-located with exposed credentials — data exfiltration risk.",
      count: kevCredential.length,
      severity: "critical",
      findings: kevCredential.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "kev=true",
    });
  }

  // 3. High EPSS (≥30%) + Critical/High CVSS (≥7) — imminent exploitation likely
  const epssHighCvss = allBlast.filter(
    (b) =>
      (b.epss_score ?? 0) >= 0.3 &&
      (b.cvss_score ?? 0) >= 7 &&
      !(b.is_kev ?? b.cisa_kev)
  );
  if (epssHighCvss.length > 0) {
    issues.push({
      id: "epss-cvss",
      title: "High Exploit Probability + Critical Severity",
      description:
        "CVEs with EPSS ≥ 30% and CVSS ≥ 7.0 — statistically likely to be exploited in the wild within 30 days.",
      count: epssHighCvss.length,
      severity: "high",
      findings: epssHighCvss.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "severity=high",
    });
  }

  // 4. Credential exposure + reachable exec tools
  const credExec = allBlast.filter(
    (b) =>
      blastCredentials(b).length > 0 &&
      blastTools(b).some((t) =>
        ["bash", "exec", "shell", "run", "execute", "subprocess"].some((kw) =>
          t.toLowerCase().includes(kw)
        )
      )
  );
  if (credExec.length > 0) {
    issues.push({
      id: "cred-exec",
      title: "Credential Exposure + Code Execution Path",
      description:
        "Exposed credentials reachable from tools with code execution capability — privilege escalation vector.",
      count: credExec.length,
      severity: "critical",
      findings: credExec.sort((a, b) => (b.risk_score ?? b.blast_score) - (a.risk_score ?? a.blast_score)),
      filter: "severity=critical",
    });
  }

  return issues.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

// Estate rollup used by the scorecard + estate-map fallback.
export interface EstateSummary {
  configuredAgents: number;
  environments: number;
  servers: number;
  credentialedServers: number;
  tools: number;
}

export function aggregateEstate(agentList: Agent[]): EstateSummary {
  const environments = new Set<string>();
  const servers = new Set<string>();
  const credentialedServers = new Set<string>();
  const tools = new Set<string>();
  const configuredAgents = agentList.filter((agent) => agent.status !== "installed-not-configured").length;

  for (const agent of agentList) {
    environments.add(agent.environment || "local");
    for (const server of agent.mcp_servers ?? []) {
      const serverKey = `${agent.name}:${server.name}`;
      servers.add(serverKey);
      if (server.has_credentials || (server.credential_env_vars?.length ?? 0) > 0) {
        credentialedServers.add(serverKey);
      }
      for (const tool of server.tools ?? []) {
        tools.add(`${server.name}:${tool.name}`);
      }
    }
  }

  return {
    configuredAgents,
    environments: environments.size,
    servers: servers.size,
    credentialedServers: credentialedServers.size,
    tools: tools.size,
  };
}
