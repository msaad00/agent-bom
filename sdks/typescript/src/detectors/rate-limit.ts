import { type Alert, AlertSeverity, createAlert } from "../types.js";
import { loadPatterns } from "../patterns.js";

export class RateLimitTracker {
  private threshold: number;
  private windowMs: number;
  private calls: Map<string, number[]> = new Map();

  constructor(threshold?: number, windowSeconds?: number) {
    const { thresholds } = loadPatterns();
    this.threshold = threshold ?? thresholds.rate_limit_default_threshold;
    this.windowMs = (windowSeconds ?? thresholds.rate_limit_default_window_seconds) * 1000;
  }

  record(toolName: string): Alert[] {
    const now = Date.now();
    let q = this.calls.get(toolName);
    if (!q) {
      q = [];
      this.calls.set(toolName, q);
    }

    q.push(now);

    // Prune old entries
    const cutoff = now - this.windowMs;
    while (q.length > 0 && q[0] < cutoff) {
      q.shift();
    }

    const alerts: Alert[] = [];
    if (q.length >= this.threshold) {
      alerts.push(
        createAlert(
          "rate_limit",
          AlertSeverity.MEDIUM,
          `Excessive tool calls: ${toolName} called ${q.length} times in ${this.windowMs / 1000}s (threshold: ${this.threshold})`,
          {
            tool: toolName,
            count: q.length,
            threshold: this.threshold,
            window_seconds: this.windowMs / 1000,
          },
        ),
      );
    }
    return alerts;
  }
}
