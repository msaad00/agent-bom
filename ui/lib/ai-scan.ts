/**
 * AI / ML supply-chain scan surface — shared types + selector metadata.
 *
 * These describe the six dedicated, synchronous scan endpoints under
 * ``/v1/scan/*`` (dataset cards, training pipelines, browser extensions,
 * model provenance, prompt scan, model files). The endpoints already ship in
 * the API, MCP tools, and CLI; this module lets the UI call them and render
 * their real results so a human operator has the same reach as an agent.
 */

export type AiScanTypeId =
  | "dataset-cards"
  | "training-pipelines"
  | "browser-extensions"
  | "model-provenance"
  | "prompt-scan"
  | "model-files";

/** A security flag as emitted by the dataset / training / model-file scanners. */
export interface AiSecurityFlag {
  severity?: string;
  type?: string;
  description?: string;
  [key: string]: unknown;
}

// ─── Request bodies ─────────────────────────────────────────────────────────

export interface DatasetCardsRequest {
  directories: string[];
}
export interface TrainingPipelinesRequest {
  directories: string[];
}
export interface BrowserExtensionsRequest {
  include_low_risk: boolean;
}
export interface ModelProvenanceRequest {
  hf_models: string[];
  ollama_models: string[];
}
export interface PromptScanRequest {
  directories: string[];
  files: string[];
}
export interface ModelFilesRequest {
  directories: string[];
  verify_hashes: boolean;
}

// ─── Response payloads ──────────────────────────────────────────────────────

export interface DatasetCard {
  name: string;
  description?: string;
  license?: string | null;
  source_file?: string;
  source_url?: string;
  version?: string;
  security_flags?: AiSecurityFlag[];
  [key: string]: unknown;
}
export interface DatasetCardsResult {
  datasets: DatasetCard[];
  source_files: string[];
  warnings: string[];
  total_datasets: number;
  flagged_count: number;
}
export interface DatasetCardsResponse {
  scan_type: "dataset-cards";
  directories: string[];
  results: DatasetCardsResult[];
}

export interface TrainingArtifact {
  name: string;
  framework?: string;
  source_file?: string;
  security_flags?: AiSecurityFlag[];
  [key: string]: unknown;
}
export interface TrainingPipelinesResult {
  training_runs: TrainingArtifact[];
  serving_configs: TrainingArtifact[];
  source_files: string[];
  warnings: string[];
  total_runs: number;
  total_serving: number;
  flagged_count: number;
}
export interface TrainingPipelinesResponse {
  scan_type: "training-pipelines";
  directories: string[];
  results: TrainingPipelinesResult[];
}

export interface BrowserExtension {
  id: string;
  name: string;
  version?: string;
  browser?: string;
  manifest_version?: number;
  permissions?: string[];
  host_permissions?: string[];
  has_native_messaging?: boolean;
  has_ai_host_access?: boolean;
  risk_level?: string;
  risk_reasons?: string[];
  path?: string;
  [key: string]: unknown;
}
export interface BrowserExtensionsResponse {
  scan_type: "browser-extensions";
  total: number;
  critical: number;
  high: number;
  extensions: BrowserExtension[];
}

export interface ProvenanceResult {
  model_id: string;
  source?: string;
  format?: string;
  is_safe_format?: boolean;
  has_digest?: boolean;
  digest?: string | null;
  is_gated?: boolean;
  has_model_card?: boolean;
  risk_level?: string;
  risk_flags?: string[];
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}
export interface ModelProvenanceResponse {
  scan_type: "model-provenance";
  total: number;
  unsafe_format: number;
  results: ProvenanceResult[];
}

export interface PromptFinding {
  severity: string;
  category?: string;
  title?: string;
  detail?: string;
  source_file?: string;
  line_number?: number | null;
  matched_text?: string;
  recommendation?: string;
  [key: string]: unknown;
}
export interface PromptScanResult {
  files_scanned: number;
  findings: PromptFinding[];
  prompt_files: string[];
  passed: boolean;
}
export interface PromptScanResponse {
  scan_type: "prompt-scan";
  results: PromptScanResult[];
}

export interface ModelFileEntry {
  path: string;
  filename?: string;
  extension?: string;
  format?: string;
  ecosystem?: string;
  size_bytes?: number;
  size_human?: string;
  security_flags?: AiSecurityFlag[];
  sha256?: string;
  [key: string]: unknown;
}
export interface ModelFilesResponse {
  scan_type: "model-files";
  total: number;
  manifest_total: number;
  unsafe: number;
  files: ModelFileEntry[];
  manifests: ModelFileEntry[];
  warnings: string[];
}

export type AiScanResponse =
  | DatasetCardsResponse
  | TrainingPipelinesResponse
  | BrowserExtensionsResponse
  | ModelProvenanceResponse
  | PromptScanResponse
  | ModelFilesResponse;

// ─── Selector metadata ──────────────────────────────────────────────────────

/** Which inputs a scan type needs — drives the input panel + submit gate. */
export type AiScanInputKind =
  | "directories"
  | "prompt"
  | "model-files"
  | "extensions"
  | "models";

export interface AiScanTypeMeta {
  id: AiScanTypeId;
  label: string;
  /** One-line plain-language description of what the scan surfaces. */
  blurb: string;
  inputKind: AiScanInputKind;
}

/**
 * The six AI supply-chain scan types, in the order the CLI/MCP group them.
 * Kept as data so the selector, input panel, and tests stay in sync.
 */
export const AI_SCAN_TYPES: readonly AiScanTypeMeta[] = [
  {
    id: "dataset-cards",
    label: "Dataset cards",
    blurb: "HuggingFace dataset cards, DVC files & data lineage — licensing and provenance gaps.",
    inputKind: "directories",
  },
  {
    id: "training-pipelines",
    label: "Training pipelines",
    blurb: "MLflow / W&B / Kubeflow artifacts — unsafe serialization, missing provenance, exposed creds.",
    inputKind: "directories",
  },
  {
    id: "browser-extensions",
    label: "Browser extensions",
    blurb: "Installed extensions — dangerous permissions, native messaging, AI-assistant host access.",
    inputKind: "extensions",
  },
  {
    id: "model-provenance",
    label: "Model provenance",
    blurb: "HuggingFace & Ollama models — safetensors vs pickle, digests, gating, model-card presence.",
    inputKind: "models",
  },
  {
    id: "prompt-scan",
    label: "Prompt scan",
    blurb: "Prompt files — injection & jailbreak patterns, hardcoded secrets, unsafe instructions.",
    inputKind: "prompt",
  },
  {
    id: "model-files",
    label: "Model files",
    blurb: "Model artifacts — pickle deserialization risk (.pkl/.pt), unsafe formats, integrity hashes.",
    inputKind: "model-files",
  },
] as const;

/** Rank a severity string (case-insensitive) for comparison. Higher = worse. */
export function aiSeverityRank(severity: string | null | undefined): number {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

/** Highest severity among a set of flags, or ``null`` when there are none. */
export function highestFlagSeverity(flags: AiSecurityFlag[] | undefined): string | null {
  if (!flags || flags.length === 0) return null;
  let best: string | null = null;
  for (const flag of flags) {
    if (best === null || aiSeverityRank(flag.severity) > aiSeverityRank(best)) {
      best = flag.severity ?? "unknown";
    }
  }
  return best;
}
