import http from "k6/http";
import { check, sleep } from "k6";

const baseUrl = (__ENV.AGENT_BOM_BASE_URL || "http://127.0.0.1:8422").replace(/\/$/, "");
const token = __ENV.AGENT_BOM_API_TOKEN || "";
const graphScanId = __ENV.AGENT_BOM_GRAPH_SCAN_ID || "";
const graphSearch = __ENV.AGENT_BOM_GRAPH_QUERY || "agent";
const graphEntityTypes = __ENV.AGENT_BOM_GRAPH_ENTITY_TYPES || "agent,server";

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

function graphParams(extra = {}) {
  const params = new URLSearchParams({
    limit: "100",
    entity_types: graphEntityTypes,
    ...extra,
  });
  if (graphScanId) {
    params.set("scan_id", graphScanId);
  }
  return params.toString();
}

export default function () {
  const overview = http.get(`${baseUrl}/v1/graph?${graphParams()}`, { headers: authHeaders() });
  check(overview, {
    "graph overview returns 200": (r) => r.status === 200,
  });

  const search = http.get(
    `${baseUrl}/v1/graph/search?${graphParams({ q: graphSearch, limit: "25" })}`,
    { headers: authHeaders() }
  );
  check(search, {
    "graph search returns 200": (r) => r.status === 200,
  });

  sleep(1);
}
