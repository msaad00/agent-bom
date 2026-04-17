import http from "k6/http";
import { check, sleep } from "k6";

const baseUrl = (__ENV.AGENT_BOM_BASE_URL || "http://127.0.0.1:8422").replace(/\/$/, "");
const token = __ENV.AGENT_BOM_API_TOKEN || "";
const batchSize = Number(__ENV.AGENT_BOM_PROXY_ALERT_BATCH || 10);

export const options = {
  vus: Number(__ENV.K6_VUS || 10),
  duration: __ENV.K6_DURATION || "60s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000"],
  },
};

function authHeaders() {
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

function buildAlerts() {
  const alerts = [];
  const now = new Date().toISOString();
  for (let i = 0; i < batchSize; i += 1) {
    alerts.push({
      type: "runtime_alert",
      ts: now,
      detector: "rate_limit",
      severity: "medium",
      message: `synthetic benchmark alert ${i}`,
      details: {
        action: "warned",
        tool_name: "filesystem.read_file",
      },
    });
  }
  return alerts;
}

export default function () {
  const payload = JSON.stringify({
    source_id: `k6-${__VU}`,
    session_id: `bench-${__ITER}`,
    alerts: buildAlerts(),
    summary: {
      total_alerts: batchSize,
      blocked_alerts: 0,
      alerts_by_detector: { rate_limit: batchSize },
      alerts_by_severity: { medium: batchSize },
    },
  });

  const response = http.post(`${baseUrl}/v1/proxy/audit`, payload, { headers: authHeaders() });
  check(response, {
    "proxy audit returns 200": (r) => r.status === 200,
  });

  sleep(1);
}
