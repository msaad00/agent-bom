import { type Alert, AlertSeverity, createAlert } from "../types.js";
import { loadPatterns, scoreSemanticInjection } from "../patterns.js";

export class ResponseInspector {
  check(toolName: string, responseText: string): Alert[] {
    const {
      responseCloakingPatterns,
      responseSvgPatterns,
      responseInvisibleChars,
      responseBase64Pattern,
      responseInjectionPatterns,
      thresholds,
    } = loadPatterns();
    const alerts: Alert[] = [];

    // HTML/CSS cloaking
    for (const { name, regex } of responseCloakingPatterns) {
      regex.lastIndex = 0;
      const matches = responseText.match(regex);
      if (matches) {
        alerts.push(
          createAlert("response_inspector", AlertSeverity.HIGH, `HTML/CSS cloaking detected: ${name} in response from ${toolName}`, {
            tool: toolName,
            pattern: name,
            category: "cloaking",
            match_count: matches.length,
          }),
        );
      }
    }

    // SVG payloads
    for (const { name, regex } of responseSvgPatterns) {
      regex.lastIndex = 0;
      const matches = responseText.match(regex);
      if (matches) {
        alerts.push(
          createAlert("response_inspector", AlertSeverity.CRITICAL, `SVG payload detected: ${name} in response from ${toolName}`, {
            tool: toolName,
            pattern: name,
            category: "svg_payload",
            match_count: matches.length,
          }),
        );
      }
    }

    // Invisible Unicode characters
    for (const { name, regex } of responseInvisibleChars) {
      regex.lastIndex = 0;
      const matches = responseText.match(regex);
      if (matches) {
        alerts.push(
          createAlert(
            "response_inspector",
            AlertSeverity.HIGH,
            `Invisible characters detected: ${name} in response from ${toolName}`,
            {
              tool: toolName,
              pattern: name,
              category: "invisible_text",
              match_count: matches.length,
            },
          ),
        );
      }
    }

    // Base64 blobs
    responseBase64Pattern.lastIndex = 0;
    const b64Matches = responseText.match(responseBase64Pattern);
    if (b64Matches) {
      alerts.push(
        createAlert(
          "response_inspector",
          AlertSeverity.MEDIUM,
          `Large base64 blob in response from ${toolName} — potential exfiltration staging`,
          {
            tool: toolName,
            category: "base64_blob",
            match_count: b64Matches.length,
            largest_length: Math.max(...b64Matches.map((m) => m.length)),
          },
        ),
      );
    }

    // Prompt injection patterns
    for (const { name, regex } of responseInjectionPatterns) {
      regex.lastIndex = 0;
      const matches = responseText.match(regex);
      if (matches) {
        alerts.push(
          createAlert(
            "response_inspector",
            AlertSeverity.CRITICAL,
            `Prompt injection detected: ${name} in response from ${toolName}`,
            {
              tool: toolName,
              pattern: name,
              category: "prompt_injection",
              match_count: matches.length,
              preview: matches[0].slice(0, 120),
            },
          ),
        );
      }
    }

    // Semantic injection scoring
    const [score, triggered] = scoreSemanticInjection(responseText);
    if (score >= thresholds.semantic_injection_suspicious) {
      const severity = score >= thresholds.semantic_injection_high ? AlertSeverity.HIGH : AlertSeverity.MEDIUM;
      alerts.push(
        createAlert(
          "response_inspector",
          severity,
          `Semantic injection risk (${score.toFixed(2)}) in response from ${toolName} — signals: ${triggered.join(", ")}`,
          {
            tool: toolName,
            category: "semantic_injection",
            score: Math.round(score * 1000) / 1000,
            signals: triggered,
          },
        ),
      );
    }

    return alerts;
  }
}
