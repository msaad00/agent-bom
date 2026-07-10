import type { ProxyAlert } from "@/lib/api";

export function proxyAlertKey(alert: ProxyAlert, index: number): string {
  return [
    alert.event_id,
    alert.ts,
    alert.detector,
    alert.tool_name,
    String(index),
  ]
    .filter(Boolean)
    .join("::");
}

/** Human-readable one-liner when API ``message`` is empty (common for demo/runtime feeds). */
export function proxyAlertSummary(alert: ProxyAlert): string {
  const message = alert.message?.trim();
  if (message) return message;

  const parts: string[] = [];
  if (alert.reason_code) parts.push(alert.reason_code.replace(/_/g, " "));
  if (alert.decision) {
    parts.push(
      alert.event_type
        ? `${alert.decision} · ${alert.event_type.replace(/_/g, " ")}`
        : alert.decision,
    );
  } else if (alert.event_type) {
    parts.push(alert.event_type.replace(/_/g, " "));
  }
  if (alert.agent_name) parts.push(alert.agent_name);
  return parts.join(" · ") || "Runtime proxy event";
}

export function proxyAlertDetailEntries(
  alert: ProxyAlert,
): Array<{ label: string; value: string }> {
  const rows: Array<{ label: string; value: string }> = [
    { label: "Severity", value: alert.severity },
    { label: "Detector", value: alert.detector },
    { label: "Tool", value: alert.tool_name },
  ];

  const optional: Array<[string, string | undefined]> = [
    ["Agent", alert.agent_name],
    ["Event type", alert.event_type?.replace(/_/g, " ")],
    ["Decision", alert.decision],
    ["Reason", alert.reason_code?.replace(/_/g, " ")],
    ["Session", alert.session_id],
    ["Source", alert.source_id],
    ["Event ID", alert.event_id],
    ["Request ID", alert.request_id],
    ["Trace ID", alert.trace_id],
  ];

  for (const [label, value] of optional) {
    if (value?.trim()) rows.push({ label, value: value.trim() });
  }

  if (alert.details && Object.keys(alert.details).length > 0) {
    for (const [key, raw] of Object.entries(alert.details)) {
      const value =
        typeof raw === "string"
          ? raw
          : raw == null
            ? ""
            : JSON.stringify(raw);
      if (value.trim()) {
        rows.push({ label: key.replace(/_/g, " "), value: value.trim() });
      }
    }
  }

  return rows;
}
