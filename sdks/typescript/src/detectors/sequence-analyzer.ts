import { type Alert, AlertSeverity, createAlert } from "../types.js";
import { loadPatterns } from "../patterns.js";

export class SequenceAnalyzer {
  private windowSize: number;
  private recentCalls: string[] = [];

  constructor(windowSize = 10) {
    this.windowSize = windowSize;
  }

  record(toolName: string): Alert[] {
    this.recentCalls.push(toolName);
    if (this.recentCalls.length > this.windowSize) {
      this.recentCalls.shift();
    }

    const { suspiciousSequences } = loadPatterns();
    const alerts: Alert[] = [];

    for (const seq of suspiciousSequences) {
      if (this.matchesSequence(this.recentCalls, seq.steps)) {
        alerts.push(
          createAlert("sequence_analyzer", AlertSeverity.HIGH, seq.description, {
            sequence_name: seq.name,
            recent_calls: this.recentCalls.slice(-seq.steps.length),
            window_size: this.windowSize,
          }),
        );
      }
    }
    return alerts;
  }

  private matchesSequence(calls: string[], patterns: string[]): boolean {
    if (calls.length < patterns.length) return false;

    let patIdx = 0;
    for (const call of calls) {
      // Normalize separators to spaces for word boundary matching
      const normalized = call.replace(/[_\-.]/g, " ");
      const bounded = new RegExp(`\\b(?:${patterns[patIdx]})\\b`, "i");
      if (bounded.test(normalized)) {
        patIdx++;
        if (patIdx === patterns.length) return true;
      }
    }
    return false;
  }

  getRecentCalls(): string[] {
    return [...this.recentCalls];
  }
}
