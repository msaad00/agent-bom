import { type Alert, AlertSeverity, createAlert } from "../types.js";
import { loadPatterns } from "../patterns.js";

export class CredentialLeakDetector {
  check(toolName: string, responseText: string): Alert[] {
    const { credentialPatterns } = loadPatterns();
    const alerts: Alert[] = [];

    for (const { name, regex } of credentialPatterns) {
      regex.lastIndex = 0;
      const matches: string[] = [];
      let m: RegExpExecArray | null;
      while ((m = regex.exec(responseText)) !== null) {
        matches.push(m[0]);
        if (!regex.global) break;
      }
      if (matches.length > 0) {
        const redacted = matches
          .slice(0, 3)
          .map((v) => (v.length > 4 ? v.slice(0, 4) + "..." : "***"));
        alerts.push(
          createAlert("credential_leak", AlertSeverity.CRITICAL, `Credential leak detected: ${name} in response from ${toolName}`, {
            tool: toolName,
            credential_type: name,
            match_count: matches.length,
            redacted_preview: redacted,
          }),
        );
      }
    }

    return alerts;
  }
}
