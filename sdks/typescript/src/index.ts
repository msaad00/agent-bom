/**
 * @agent-bom/runtime — Runtime security detectors for MCP traffic.
 *
 * 8 detectors that analyze MCP JSON-RPC traffic in real-time:
 * - ToolDriftDetector — rug pull detection (new tools after baseline)
 * - ArgumentAnalyzer — shell injection, path traversal, credential values
 * - CredentialLeakDetector — API keys/tokens in tool responses
 * - RateLimitTracker — excessive tool calls per sliding window
 * - SequenceAnalyzer — suspicious multi-step patterns (exfiltration, recon)
 * - ResponseInspector — cloaking, SVG payloads, invisible chars, prompt injection
 * - VectorDBInjectionDetector — cache poisoning in RAG/vector DB responses
 */

export { AlertSeverity, createAlert } from "./types.js";
export type { Alert, PatternDef, WeightedPatternDef, SequenceDef, Thresholds } from "./types.js";

export { loadPatterns, scoreSemanticInjection } from "./patterns.js";
export type { CompiledPattern, CompiledWeightedPattern, LoadedPatterns } from "./patterns.js";

export { ToolDriftDetector } from "./detectors/tool-drift.js";
export { ArgumentAnalyzer } from "./detectors/argument-analyzer.js";
export { CredentialLeakDetector } from "./detectors/credential-leak.js";
export { RateLimitTracker } from "./detectors/rate-limit.js";
export { SequenceAnalyzer } from "./detectors/sequence-analyzer.js";
export { ResponseInspector } from "./detectors/response-inspector.js";
export { VectorDBInjectionDetector } from "./detectors/vector-db-injection.js";
