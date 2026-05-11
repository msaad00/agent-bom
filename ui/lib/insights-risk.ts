import type { Agent, BlastRadius, ScanResult, Vulnerability } from "@/lib/api";
import type { EpssVsCvssPoint, PipelineStats } from "@/components/charts";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

const SEVERITY_SCORE: Record<string, number> = {
  critical: 90,
  high: 70,
  medium: 45,
  low: 20,
  none: 5,
};
const DEFAULT_SEVERITY_SCORE = 20;

function normalizeSeverity(severity: string | undefined): string {
  const normalized = (severity ?? "low").toLowerCase();
  return normalized === "none" ? "low" : normalized;
}

function vulnerabilityPriority(vuln: Vulnerability): number {
  const severity = normalizeSeverity(vuln.severity);
  const severityScore = SEVERITY_SCORE[severity] ?? DEFAULT_SEVERITY_SCORE;
  const cvssScore = typeof vuln.cvss_score === "number" ? vuln.cvss_score * 10 : 0;
  const epssBonus = typeof vuln.epss_score === "number" ? Math.min(15, vuln.epss_score * 15) : 0;
  const kevBonus = vuln.is_kev ?? vuln.cisa_kev ? 10 : 0;
  return Math.min(100, Math.max(severityScore, cvssScore) + epssBonus + kevBonus);
}

export function blastPriority(blast: BlastRadius): number {
  const raw = typeof blast.risk_score === "number" ? blast.risk_score : blast.blast_score;
  if (Number.isFinite(raw) && raw > 0) {
    return raw <= 10 ? raw * 10 : raw;
  }
  const severityScore = SEVERITY_SCORE[normalizeSeverity(blast.severity)] ?? DEFAULT_SEVERITY_SCORE;
  const cvssScore = typeof blast.cvss_score === "number" ? blast.cvss_score * 10 : 0;
  const epssBonus = typeof blast.epss_score === "number" ? Math.min(15, blast.epss_score * 15) : 0;
  const kevBonus = blast.is_kev ?? blast.cisa_kev ? 10 : 0;
  return Math.min(100, Math.max(severityScore, cvssScore) + epssBonus + kevBonus);
}

export function buildDerivedBlastRadius(agents: Agent[]): BlastRadius[] {
  const derived: BlastRadius[] = [];
  for (const agent of agents) {
    for (const server of agent.mcp_servers ?? []) {
      for (const pkg of server.packages ?? []) {
        for (const vuln of pkg.vulnerabilities ?? []) {
          const score = vulnerabilityPriority(vuln);
          derived.push({
            vulnerability_id: vuln.id,
            severity: normalizeSeverity(vuln.severity),
            package: pkg.name,
            ecosystem: pkg.ecosystem,
            affected_agents: [agent.name],
            affected_servers: [server.name],
            exposed_credentials: [],
            reachable_tools: [],
            risk_score: score / 10,
            blast_score: score,
            cvss_score: vuln.cvss_score,
            epss_score: vuln.epss_score,
            is_kev: vuln.is_kev,
            cisa_kev: vuln.cisa_kev,
            fixed_version: vuln.fixed_version,
            attack_vector_summary: "Derived from package vulnerability data because graph blast radius was not populated for this scan.",
          });
        }
      }
    }
  }
  return derived;
}

export function effectiveBlastRadius(result: ScanResult | null): BlastRadius[] {
  if (!result) return [];
  const blasts = result.blast_radius ?? [];
  return blasts.length > 0 ? blasts : buildDerivedBlastRadius(result.agents ?? []);
}

export function buildPipelineStats(result: ScanResult): PipelineStats {
  let servers = 0;
  let packages = 0;
  for (const agent of result.agents) {
    servers += agent.mcp_servers.length;
    for (const srv of agent.mcp_servers) {
      packages += srv.packages.length;
    }
  }

  const blasts = effectiveBlastRadius(result);
  let critical = 0;
  let high = 0;
  let vulnerabilities = 0;
  let kev = 0;

  const seen = new Set<string>();
  for (const br of blasts) {
    if (seen.has(br.vulnerability_id)) continue;
    seen.add(br.vulnerability_id);
    vulnerabilities++;
    const severity = normalizeSeverity(br.severity);
    if (severity === "critical") critical++;
    if (severity === "high") high++;
    if (br.is_kev ?? br.cisa_kev) kev++;
  }

  return {
    agents: result.agents.length,
    servers,
    packages,
    vulnerabilities,
    critical,
    high,
    kev,
  };
}

export function buildEpssVsCvss(blasts: BlastRadius[]): EpssVsCvssPoint[] {
  const seen = new Set<string>();
  const out: EpssVsCvssPoint[] = [];
  for (const br of blasts) {
    if (seen.has(br.vulnerability_id)) continue;
    seen.add(br.vulnerability_id);
    if (!br.cvss_score && !br.epss_score) continue;
    out.push({
      cve: br.vulnerability_id,
      cvss: br.cvss_score ?? 0,
      epss: br.epss_score ?? 0,
      blast: blastPriority(br),
      severity: normalizeSeverity(br.severity),
      kev: !!(br.is_kev ?? br.cisa_kev),
      package: br.package,
    });
  }
  return out.sort((a, b) => {
    const severityDelta = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    return severityDelta || b.blast - a.blast;
  });
}

export interface BlastRadiusSummary {
  name: string;
  score: number;
  severity: string;
  vulnerability_count: number;
  agent_count: number;
  server_count: number;
}

export function buildBlastRadiusSummary(blasts: BlastRadius[], limit = 8): BlastRadiusSummary[] {
  const grouped = new Map<
    string,
    {
      score: number;
      severity: string;
      vulnerabilities: Set<string>;
      agents: Set<string>;
      servers: Set<string>;
    }
  >();

  for (const blast of blasts) {
    const name = blast.package ?? blast.vulnerability_id;
    const entry = grouped.get(name) ?? {
      score: 0,
      severity: "low",
      vulnerabilities: new Set<string>(),
      agents: new Set<string>(),
      servers: new Set<string>(),
    };
    const severity = normalizeSeverity(blast.severity);
    if ((SEVERITY_RANK[severity] ?? 0) > (SEVERITY_RANK[entry.severity] ?? 0)) {
      entry.severity = severity;
    }
    entry.score = Math.max(entry.score, blastPriority(blast));
    entry.vulnerabilities.add(blast.vulnerability_id);
    for (const agent of blast.affected_agents ?? []) {
      entry.agents.add(agent);
    }
    for (const server of blast.affected_servers ?? []) {
      entry.servers.add(server);
    }
    grouped.set(name, entry);
  }

  return [...grouped.entries()]
    .map(([name, entry]) => ({
      name,
      score: entry.score,
      severity: entry.severity,
      vulnerability_count: entry.vulnerabilities.size,
      agent_count: entry.agents.size,
      server_count: entry.servers.size,
    }))
    .sort((left, right) => right.score - left.score || right.vulnerability_count - left.vulnerability_count || left.name.localeCompare(right.name))
    .slice(0, limit);
}
