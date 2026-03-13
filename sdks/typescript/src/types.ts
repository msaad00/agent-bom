/**
 * Core types for agent-bom runtime security detectors.
 *
 * These types mirror the Python implementation in
 * src/agent_bom/runtime/detectors.py to ensure cross-language parity.
 */

export enum AlertSeverity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

export interface Alert {
  readonly type: "runtime_alert";
  readonly detector: string;
  readonly severity: AlertSeverity;
  readonly message: string;
  readonly details: Record<string, unknown>;
  readonly ts: string;
}

export function createAlert(
  detector: string,
  severity: AlertSeverity,
  message: string,
  details: Record<string, unknown> = {},
): Alert {
  return {
    type: "runtime_alert",
    detector,
    severity,
    message,
    details,
    ts: new Date().toISOString(),
  };
}

/** Pattern definition loaded from patterns.json */
export interface PatternDef {
  name: string;
  pattern: string;
  flags: string;
}

/** Weighted pattern for semantic injection scoring */
export interface WeightedPatternDef extends PatternDef {
  weight: number;
}

/** Suspicious sequence definition */
export interface SequenceDef {
  name: string;
  steps: string[];
  description: string;
}

/** Threshold constants from patterns.json */
export interface Thresholds {
  semantic_injection_suspicious: number;
  semantic_injection_high: number;
  rate_limit_default_threshold: number;
  rate_limit_default_window_seconds: number;
  max_message_bytes: number;
  client_readline_timeout_seconds: number;
  replay_window_seconds: number;
  replay_max_entries: number;
}
