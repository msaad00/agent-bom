import { type Alert, AlertSeverity, createAlert } from "../types.js";
import { loadPatterns } from "../patterns.js";

export class ArgumentAnalyzer {
  check(toolName: string, args: Record<string, unknown>): Alert[] {
    const { dangerousArgPatterns, cortexModelPatterns } = loadPatterns();
    const alerts: Alert[] = [];

    for (const [key, value] of Object.entries(args)) {
      if (typeof value !== "string") continue;

      for (const { name, regex } of dangerousArgPatterns) {
        // Reset lastIndex for global regexes
        regex.lastIndex = 0;
        if (regex.test(value)) {
          alerts.push(
            createAlert("argument_analyzer", AlertSeverity.HIGH, `Dangerous pattern "${name}" in argument "${key}"`, {
              tool: toolName,
              argument: key,
              pattern: name,
              value_preview: value.slice(0, 100),
            }),
          );
        }
      }

      // Cortex model detection (INFO level)
      for (const { name, regex } of cortexModelPatterns) {
        regex.lastIndex = 0;
        const match = regex.exec(value);
        if (match) {
          alerts.push(
            createAlert("argument_analyzer", AlertSeverity.INFO, `Cortex AI model invocation: ${name}`, {
              tool: toolName,
              category: "cortex_model_usage",
              pattern: name,
              model: match[1] ?? "",
            }),
          );
        }
      }
    }

    return alerts;
  }
}
