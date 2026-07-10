export type RepoScanSurface = {
  id: string;
  label: string;
  detail: string;
  languages?: string[] | undefined;
};

/** Honest catalog of what a public-repo scan auto-detects today (static parse only). */
export const REPO_SCAN_SURFACES: RepoScanSurface[] = [
  {
    id: "agent-frameworks",
    label: "Agent frameworks",
    detail: "LangChain, CrewAI, OpenAI Agents SDK, ADK, LlamaIndex, AutoGen, and related Python stacks",
    languages: ["Python"],
  },
  {
    id: "mcp-config",
    label: "MCP & agent configs",
    detail: "mcp.json, Claude/Cursor/Windsurf instruction files, MCP server references in markdown",
    languages: ["JSON", "Markdown", "YAML"],
  },
  {
    id: "skills",
    label: "Skills & instructions",
    detail: "SKILL.md, AGENTS.md, CLAUDE.md — package refs, credential env vars, behavioral audit",
    languages: ["Markdown"],
  },
  {
    id: "terraform",
    label: "Terraform & cloud AI infra",
    detail: "Bedrock, Vertex, Azure OpenAI, Snowflake Cortex resources; provider versions; hardcoded secrets",
    languages: ["HCL"],
  },
  {
    id: "iac",
    label: "IaC & deployment configs",
    detail: "Kubernetes, CloudFormation, Helm, Docker, dbt — misconfigurations and AI-adjacent resources",
    languages: ["YAML", "JSON", "HCL"],
  },
  {
    id: "github-actions",
    label: "CI/CD pipelines",
    detail: "GitHub Actions workflows that invoke agents, models, or supply-chain steps",
    languages: ["YAML"],
  },
  {
    id: "dependencies",
    label: "Dependencies & supply chain",
    detail: "uv.lock, requirements.txt, poetry.lock, package-lock.json, and other manifests — pinned versions with OSV/CVE enrichment when enabled",
    languages: ["Python", "Node", "Go", "Ruby", "Rust", "…"],
  },
  {
    id: "secrets",
    label: "Secrets & credentials",
    detail: "Hardcoded API keys, tokens, private keys, and connection strings in source and config files",
    languages: ["Python", "TS/JS", "YAML", "JSON", "env"],
  },
  {
    id: "weak-crypto",
    label: "Weak cryptography",
    detail: "MD5/SHA-1 hashes, DES/RC4 ciphers, ECB mode, and deprecated TLS protocol usage in application code",
    languages: ["Python", "TS/JS", "Go", "Java", "…"],
  },
  {
    id: "ingestion",
    label: "Data & ingestion code",
    detail: "Notebooks, ETL/pipeline Python, and infra wiring when present in the repo tree",
    languages: ["Python", "SQL"],
  },
];

export function repoScanLanguageSummary(): string {
  const languages = new Set<string>();
  for (const surface of REPO_SCAN_SURFACES) {
    for (const language of surface.languages ?? []) {
      if (language !== "…") languages.add(language);
    }
  }
  return `${languages.size}+ languages and config formats`;
}
