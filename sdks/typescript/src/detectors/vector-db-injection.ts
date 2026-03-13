import { type Alert, AlertSeverity, createAlert } from "../types.js";
import { loadPatterns } from "../patterns.js";
import { ResponseInspector } from "./response-inspector.js";

const VECTOR_TOOL_PATTERN =
  /(?:similarity[\s_]search|semantic[\s_]search|vector[\s_](?:search|query|lookup)|retriev(?:e|al)|fetch[\s_](?:context|docs?|chunks?)|rag[\s_](?:query|search)|search[\s_](?:docs?|knowledge|embeddings?)|query[\s_](?:index|store|db|database)|get[\s_]context|lookup[\s_](?:docs?|knowledge))/i;

export class VectorDBInjectionDetector {
  private inspector = new ResponseInspector();

  isVectorTool(toolName: string): boolean {
    return VECTOR_TOOL_PATTERN.test(toolName);
  }

  check(toolName: string, responseText: string): Alert[] {
    const { responseInjectionPatterns } = loadPatterns();
    const alerts: Alert[] = [];
    const isVector = this.isVectorTool(toolName);

    // Injection patterns — always check
    for (const { name, regex } of responseInjectionPatterns) {
      regex.lastIndex = 0;
      const matches = responseText.match(regex);
      if (matches) {
        alerts.push(
          createAlert(
            "vector_db_injection",
            AlertSeverity.CRITICAL,
            `${isVector ? "Cache poisoning" : "Content injection"} detected: ${name} in ${isVector ? "vector DB retrieval" : "tool response"} from ${toolName}`,
            {
              tool: toolName,
              pattern: name,
              category: isVector ? "cache_poison" : "content_injection",
              is_vector_tool: isVector,
              match_count: matches.length,
              preview: matches[0].slice(0, 120),
            },
          ),
        );
      }
    }

    // For vector tools, run full cloaking/SVG/invisible checks
    if (isVector) {
      for (const alert of this.inspector.check(toolName, responseText)) {
        alerts.push(
          createAlert(
            "vector_db_injection",
            alert.severity === AlertSeverity.HIGH ? AlertSeverity.CRITICAL : alert.severity,
            alert.message,
            {
              ...alert.details,
              category: "cache_poison_" + ((alert.details.category as string) ?? "unknown"),
            },
          ),
        );
      }
    }

    return alerts;
  }
}
