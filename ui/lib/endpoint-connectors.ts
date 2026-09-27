/** Endpoint evidence is separate from enrolled agents and policy compliance. */
export interface EndpointConnection {
  id: string;
  tenant_id: string;
  name: string;
  provider: "jamf" | "crowdstrike";
  account_id: string;
  jamf_url: string;
  region: string;
  client_id: string;
  page_size: number;
  freshness_hours: number;
  created_at: string;
  enabled: boolean;
}
export interface EndpointSync {
  run_id: string;
  connection_id: string;
  tenant_id: string;
  started_at: string;
  updated_at: string;
  status: "collecting" | "partial" | "complete" | "failed";
  pages: number;
  device_count: number;
  expected_count: number | null;
  gap: string;
}
export interface EndpointDevice {
  device_id: string;
  source: string;
  hostname: string;
  os_version: string;
  managed: boolean | null;
  compliant: boolean | null;
  disk_encrypted: boolean | null;
  last_seen: string;
  observed_at: string;
  attributes: Record<string, unknown>;
}
export interface EndpointInventory {
  recent_receipts?: EndpointSync[];
  schema_version: string;
  sync: EndpointSync | null;
  devices: EndpointDevice[];
  offset: number;
  limit: number;
}
export interface EndpointConnections {
  connections: { connection: EndpointConnection; sync: EndpointSync | null }[];
}
export interface EndpointConnectionCreate {
  name: string;
  provider: "jamf" | "crowdstrike";
  account_id: string;
  jamf_url?: string;
  region?: string;
  client_id: string;
  client_secret: string;
}
export function postureLabel(value: boolean | null): string {
  return value === true ? "Yes" : value === false ? "No" : "Unknown";
}
