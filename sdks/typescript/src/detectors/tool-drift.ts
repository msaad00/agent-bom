import { type Alert, AlertSeverity, createAlert } from "../types.js";

export class ToolDriftDetector {
  baseline: Set<string> | null = null;

  setBaseline(tools: string[]): void {
    this.baseline = new Set(tools);
  }

  check(currentTools: string[]): Alert[] {
    const current = new Set(currentTools);
    if (this.baseline === null) {
      this.baseline = current;
      return [];
    }

    const alerts: Alert[] = [];
    const newTools = [...current].filter((t) => !this.baseline!.has(t));
    const removed = [...this.baseline].filter((t) => !current.has(t));

    if (newTools.length > 0) {
      alerts.push(
        createAlert("tool_drift", AlertSeverity.HIGH, `New tools detected after baseline: ${newTools.join(", ")}`, {
          new_tools: newTools,
          baseline_count: this.baseline.size,
        }),
      );
    }
    if (removed.length > 0) {
      alerts.push(
        createAlert("tool_drift", AlertSeverity.MEDIUM, `Tools removed after baseline: ${removed.join(", ")}`, {
          removed_tools: removed,
          baseline_count: this.baseline.size,
        }),
      );
    }
    return alerts;
  }
}
