import http from "k6/http";
import { check, sleep } from "k6";

const baseUrl = (__ENV.AGENT_BOM_BASE_URL || "http://127.0.0.1:8422").replace(/\/$/, "");
const token = __ENV.AGENT_BOM_API_TOKEN || "";

export const options = {
  vus: Number(__ENV.K6_VUS || 10),
  duration: __ENV.K6_DURATION || "60s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000"],
  },
};

function authHeaders() {
  const headers = { Accept: "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

export default function () {
  const health = http.get(`${baseUrl}/health`, { headers: authHeaders() });
  check(health, {
    "health returns 200": (r) => r.status === 200,
  });

  if (token) {
    const fleet = http.get(`${baseUrl}/v1/fleet?limit=25`, { headers: authHeaders() });
    check(fleet, {
      "fleet returns 200": (r) => r.status === 200,
    });

    const stats = http.get(`${baseUrl}/v1/fleet/stats`, { headers: authHeaders() });
    check(stats, {
      "fleet stats returns 200": (r) => r.status === 200,
    });
  }

  sleep(1);
}
