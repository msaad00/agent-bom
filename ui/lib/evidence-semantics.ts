/** Canonical evidence vocabularies mirrored from the Python contract. */

export const EVIDENCE_BASES = ["observed", "runtime_observed", "inferred", "modeled"] as const;
export type EvidenceBasis = (typeof EVIDENCE_BASES)[number];

export const EVIDENCE_STATUSES = ["complete", "partial", "unavailable", "failed"] as const;
export type EvidenceStatus = (typeof EVIDENCE_STATUSES)[number];

export const FRESHNESS_STATUSES = ["fresh", "stale", "unknown"] as const;
export type FreshnessStatus = (typeof FRESHNESS_STATUSES)[number];

export const EVIDENCE_STAGES = [
  "collection",
  "normalization",
  "catalog_lookup",
  "persistence",
  "graph_join",
  "analysis",
] as const;
export type EvidenceStage = (typeof EVIDENCE_STAGES)[number];

export const REACHABILITY_VERDICTS = ["confirmed", "likely", "unknown", "unlikely"] as const;
export type ReachabilityVerdict = (typeof REACHABILITY_VERDICTS)[number];

export const EXPLOITABILITY_VERDICTS = ["exploitable", "not_exploitable", "unknown"] as const;
export type ExploitabilityVerdict = (typeof EXPLOITABILITY_VERDICTS)[number];

export interface EvidenceFreshness {
  status: FreshnessStatus;
  observed_at?: string | null;
  valid_until?: string | null;
  evaluated_at: string;
  max_age_seconds?: number | null;
}

export interface EvidenceProvenance {
  schema_version: "evidence-provenance.v1";
  evidence_id: string;
  basis?: EvidenceBasis | null;
  status: EvidenceStatus;
  source: string;
  source_ids: string[];
  confidence?: number | null;
  freshness?: EvidenceFreshness | null;
  reason_codes: string[];
}

export interface CompletenessEntry {
  stage: EvidenceStage;
  component: string;
  status: EvidenceStatus;
  requested: boolean;
  affects_coverage: boolean;
  returned_count?: number | null;
  expected_count?: number | null;
  reason_codes: string[];
}

export interface EvidenceCompletenessLedger {
  schema_version: "evidence-completeness.v1";
  entries: CompletenessEntry[];
  overall_status: EvidenceStatus;
}

interface EvidenceDimension {
  status: EvidenceStatus;
  evidence_refs: string[];
  reason_codes: string[];
}

export interface ExposureAssessment extends EvidenceDimension {
  internet_exposed?: boolean | null;
  entry_point_ids: string[];
  credential_ids: string[];
  tool_ids: string[];
}

export interface ReachabilityDimension extends EvidenceDimension {
  verdict?: ReachabilityVerdict | null;
  min_hops?: number | null;
  path_ids: string[];
}

export interface ExploitabilityDimension extends EvidenceDimension {
  verdict?: ExploitabilityVerdict | null;
  attack_vector?: string | null;
  attack_complexity?: string | null;
  privileges_required?: string | null;
  user_interaction?: string | null;
}

export interface LikelihoodDimension extends EvidenceDimension {
  probability?: number | null;
  method?: string | null;
  model_version?: string | null;
  as_of?: string | null;
  known_exploited?: boolean | null;
}

export interface ImpactDimension extends EvidenceDimension {
  technical_categories: string[];
  business_criticality?: string | null;
  data_sensitivity?: string | null;
  affected_asset_count?: number | null;
}

export type RiskFactor = "exposure" | "reachability" | "exploitability" | "likelihood" | "impact";

export interface RiskDimension extends EvidenceDimension {
  score?: number | null;
  method?: string | null;
  method_version?: string | null;
  factor_dimensions: RiskFactor[];
}

export interface SecurityDimensions {
  schema_version: "security-dimensions.v1";
  exposure: ExposureAssessment;
  reachability: ReachabilityDimension;
  exploitability: ExploitabilityDimension;
  likelihood: LikelihoodDimension;
  impact: ImpactDimension;
  risk: RiskDimension;
  evidence: EvidenceProvenance[];
  completeness: EvidenceCompletenessLedger;
}
