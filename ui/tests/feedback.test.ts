import { describe, expect, it } from "vitest";

import { buildIssueUrl, buildSupportBundle } from "@/lib/feedback";

describe("feedback helpers", () => {
  it("builds GitHub issue template links", () => {
    const url = buildIssueUrl("bug_report.yml", "bug(ui): issue from /proxy");
    expect(url).toContain("template=bug_report.yml");
    expect(url).toContain("title=bug%28ui%29%3A+issue+from+%2Fproxy");
  });

  it("builds a support bundle with deployment and auth context", () => {
    const bundle = buildSupportBundle({
      from: "/gateway",
      currentUrl: "https://agent-bom.internal.example.com/help?from=%2Fgateway",
      userAgent: "VitestBrowser/1.0",
      version: {
        version: "0.81.1",
        api_version: "v1",
        python_package: "agent-bom",
      },
      authDebug: {
        authenticated: true,
        auth_required: true,
        configured_modes: ["oidc"],
        recommended_ui_mode: "session",
        auth_method: "oidc",
        subject: "alice@example.com",
        role: "admin",
        tenant_id: "tenant-alpha",
        oidc_issuer_suffix: "okta.example.com",
        api_key_id_prefix: null,
        request_id: "req-1",
        trace_id: "trace-1",
        span_id: "span-1",
      },
      counts: {
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
        total: 10,
        kev: 1,
        compound_issues: 1,
        deployment_mode: "hybrid",
        has_fleet_ingest: true,
        has_gateway: true,
        has_proxy: true,
        has_cluster_scan: true,
        has_local_scan: false,
        scan_sources: ["fleet", "cluster"],
      },
    });

    expect(bundle).toContain("Page opened from: `/gateway`");
    expect(bundle).toContain("Deployment mode: `hybrid`");
    expect(bundle).toContain("Tenant: `tenant-alpha`");
    expect(bundle).toContain("Trace ID: `trace-1`");
    expect(bundle).toContain("Scan sources: `fleet, cluster`");
  });
});
