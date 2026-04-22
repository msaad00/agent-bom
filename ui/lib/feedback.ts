import type { AuthDebugResponse, PostureCountsResponse, VersionInfo } from "./api";

export function buildIssueUrl(template: string, title: string) {
  const params = new URLSearchParams({
    template,
    title,
  });
  return `https://github.com/msaad00/agent-bom/issues/new?${params.toString()}`;
}

export function buildSupportBundle(input: {
  from: string;
  currentUrl?: string;
  userAgent?: string;
  version: VersionInfo | null;
  authDebug: AuthDebugResponse | null;
  counts: PostureCountsResponse | null;
}) {
  const { authDebug, counts, currentUrl, from, userAgent, version } = input;
  const lines = [
    "# agent-bom support bundle",
    "",
    "## Product surface",
    "- UI role: browser control-plane for the self-hosted agent-bom product",
    `- Page opened from: \`${from}\``,
    `- Browser URL: \`${currentUrl ?? "/help"}\``,
    "",
    "## Version",
    `- UI/API version: \`${version?.version ?? "unknown"}\``,
    `- API version: \`${version?.api_version ?? "unknown"}\``,
    `- Python package: \`${version?.python_package ?? "unknown"}\``,
    "",
    "## Deployment context",
    `- Deployment mode: \`${counts?.deployment_mode ?? "unknown"}\``,
    `- Scan sources: \`${(counts?.scan_sources ?? []).join(", ") || "unknown"}\``,
    `- Fleet ingest: \`${counts?.has_fleet_ingest ?? false}\``,
    `- Gateway detected: \`${counts?.has_gateway ?? false}\``,
    `- Proxy detected: \`${counts?.has_proxy ?? false}\``,
    `- Cluster scan detected: \`${counts?.has_cluster_scan ?? false}\``,
    `- Local scan detected: \`${counts?.has_local_scan ?? false}\``,
    "",
    "## Auth/debug context",
    `- Authenticated: \`${authDebug?.authenticated ?? false}\``,
    `- Auth required: \`${authDebug?.auth_required ?? false}\``,
    `- Auth method: \`${authDebug?.auth_method ?? "unknown"}\``,
    `- Role: \`${authDebug?.role ?? "unknown"}\``,
    `- Tenant: \`${authDebug?.tenant_id ?? "unknown"}\``,
    `- Recommended UI mode: \`${authDebug?.recommended_ui_mode ?? "unknown"}\``,
    `- Trace ID: \`${authDebug?.trace_id ?? "unknown"}\``,
    `- Request ID: \`${authDebug?.request_id ?? "unknown"}\``,
    "",
    "## Browser",
    `- User agent: \`${userAgent ?? "unknown"}\``,
    "",
    "## What happened",
    "- Describe the bug, feedback, or missing workflow here.",
  ];
  return lines.join("\n");
}
