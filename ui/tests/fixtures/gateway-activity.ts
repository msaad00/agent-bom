import type { GatewayActivity } from "@/lib/gateway-activity";

export function activity(index: number): GatewayActivity {
  return { tenant_id: "tenant-a", event_id: `event-${index}`, ingest_ordinal: index, event_type: "gateway.tool_call.allowed", event_timestamp: "2026-09-08T12:00:00Z", ingested_at: "2026-09-08T12:00:01Z", agent_id: "payroll-agent", identity_id: "identity-a", upstream: "filesystem", tool: "read_file", decision: "allow", profile_id: "finance-prod", profile_revision: 3, blueprint_id: "finance", blueprint_revision: 1, policy_ids: ["policy-finance"], policy_id: "policy-finance", evidence_id: "evidence-7", trace_id: "trace-7", reason_code: "resolved", data_action: "", development_mode: false };
}
