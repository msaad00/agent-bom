import { describe, expect, it } from "vitest";

import {
  attackPathKey,
  attackPathSequenceLabels,
  buildSecurityGraphHref,
  labelsForAttackPathType,
  mapAttackPathNodeType,
  matchesAttackPathFocus,
  moveAttackPathSelection,
  recommendedInteractionRiskActions,
  recommendedAttackPathActions,
  summarizeInteractionRisks,
  toAttackCardNodes,
} from "@/lib/attack-paths";
import { EntityType, type AttackPath, type UnifiedNode } from "@/lib/graph-schema";

describe("attack path helpers", () => {
  it("builds a stable key from source, target, and hops", () => {
    const path: AttackPath = {
      source: "pkg",
      target: "agent",
      hops: ["cve", "pkg", "server", "agent"],
      edges: [],
      composite_risk: 9.2,
      summary: "critical path",
      credential_exposure: [],
      tool_exposure: [],
      vuln_ids: ["CVE-2026-0001"],
    };

    expect(attackPathKey(path)).toBe("pkg::agent::cve->pkg->server->agent");
  });

  it("moves attack-path selection left and right with wraparound", () => {
    const paths: AttackPath[] = [
      {
        source: "a",
        target: "b",
        hops: ["a", "b"],
        edges: [],
        composite_risk: 9.1,
        summary: "path one",
        credential_exposure: [],
        tool_exposure: [],
        vuln_ids: [],
      },
      {
        source: "b",
        target: "c",
        hops: ["b", "c"],
        edges: [],
        composite_risk: 8.4,
        summary: "path two",
        credential_exposure: [],
        tool_exposure: [],
        vuln_ids: [],
      },
    ];

    const firstKey = attackPathKey(paths[0]!);
    const secondKey = attackPathKey(paths[1]!);

    expect(moveAttackPathSelection(paths, firstKey, 1)).toBe(secondKey);
    expect(moveAttackPathSelection(paths, secondKey, 1)).toBe(firstKey);
    expect(moveAttackPathSelection(paths, firstKey, -1)).toBe(secondKey);
  });

  it("maps supported entity types into attack card node types", () => {
    expect(mapAttackPathNodeType(EntityType.VULNERABILITY)).toBe("cve");
    expect(mapAttackPathNodeType(EntityType.PACKAGE)).toBe("package");
    expect(mapAttackPathNodeType(EntityType.SERVER)).toBe("server");
    expect(mapAttackPathNodeType(EntityType.AGENT)).toBe("agent");
    expect(mapAttackPathNodeType(EntityType.CREDENTIAL)).toBe("credential");
    expect(mapAttackPathNodeType(EntityType.TOOL)).toBeNull();
  });

  it("drops unknown hops and preserves severity for supported nodes", () => {
    const path: AttackPath = {
      source: "cve-1",
      target: "agent-1",
      hops: ["cve-1", "tool-1", "agent-1"],
      edges: [],
      composite_risk: 7.8,
      summary: "mixed path",
      credential_exposure: [],
      tool_exposure: [],
      vuln_ids: ["CVE-2026-0002"],
    };

    const nodes = new Map<string, UnifiedNode>([
      [
        "cve-1",
        {
          id: "cve-1",
          entity_type: EntityType.VULNERABILITY,
          label: "CVE-2026-0002",
          category_uid: 2,
          class_uid: 2001,
          type_uid: 0,
          status: "active",
          risk_score: 9,
          severity: "critical",
          severity_id: 5,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "tool-1",
        {
          id: "tool-1",
          entity_type: EntityType.TOOL,
          label: "run_shell",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 4,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "agent-1",
        {
          id: "agent-1",
          entity_type: EntityType.AGENT,
          label: "Claude Desktop",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
    ]);

    expect(toAttackCardNodes(path, nodes)).toEqual([
      { type: "cve", label: "CVE-2026-0002", severity: "critical" },
      { type: "agent", label: "Claude Desktop", severity: "high" },
    ]);
  });

  it("builds a focused security-graph href from canonical context", () => {
    expect(
      buildSecurityGraphHref({
        scanId: "scan-123",
        cve: "CVE-2026-0002",
        packageName: "flask",
        agentName: "Claude Desktop",
      }),
    ).toBe("/security-graph?scan=scan-123&cve=CVE-2026-0002&package=flask&agent=Claude+Desktop");
  });

  it("matches a focused attack path by cve, package, and agent labels", () => {
    const path: AttackPath = {
      source: "cve-1",
      target: "agent-1",
      hops: ["cve-1", "pkg-1", "server-1", "agent-1"],
      edges: [],
      composite_risk: 8.4,
      summary: "focused path",
      credential_exposure: [],
      tool_exposure: [],
      vuln_ids: ["CVE-2026-7777"],
    };

    const nodes = new Map<string, UnifiedNode>([
      [
        "cve-1",
        {
          id: "cve-1",
          entity_type: EntityType.VULNERABILITY,
          label: "CVE-2026-7777",
          category_uid: 2,
          class_uid: 2001,
          type_uid: 0,
          status: "active",
          risk_score: 9,
          severity: "critical",
          severity_id: 5,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "pkg-1",
        {
          id: "pkg-1",
          entity_type: EntityType.PACKAGE,
          label: "flask",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "server-1",
        {
          id: "server-1",
          entity_type: EntityType.SERVER,
          label: "sqlite-mcp",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "agent-1",
        {
          id: "agent-1",
          entity_type: EntityType.AGENT,
          label: "Claude Desktop",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
    ]);

    expect(
      matchesAttackPathFocus(path, nodes, {
        cve: "CVE-2026-7777",
        packageName: "flask",
        agentName: "Claude Desktop",
      }),
    ).toBe(true);

    expect(
      matchesAttackPathFocus(path, nodes, {
        cve: "CVE-2026-7777",
        packageName: "requests",
      }),
    ).toBe(false);
  });

  it("returns unique labels for a requested attack-path node type", () => {
    const path: AttackPath = {
      source: "cve-1",
      target: "agent-1",
      hops: ["agent-1", "agent-2", "agent-1", "cred-1"],
      edges: [],
      composite_risk: 5.3,
      summary: "duplicate agent labels",
      credential_exposure: [],
      tool_exposure: [],
      vuln_ids: [],
    };

    const nodes = new Map<string, UnifiedNode>([
      [
        "agent-1",
        {
          id: "agent-1",
          entity_type: EntityType.AGENT,
          label: "Claude Desktop",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 5,
          severity: "medium",
          severity_id: 3,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "agent-2",
        {
          id: "agent-2",
          entity_type: EntityType.AGENT,
          label: "Cursor",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 5,
          severity: "medium",
          severity_id: 3,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "cred-1",
        {
          id: "cred-1",
          entity_type: EntityType.CREDENTIAL,
          label: "ANTHROPIC_API_KEY",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
    ]);

    expect(labelsForAttackPathType(path, nodes, "agent")).toEqual(["Claude Desktop", "Cursor"]);
  });

  it("returns ordered labels for the selected path sequence", () => {
    const path: AttackPath = {
      source: "cve-1",
      target: "agent-1",
      hops: ["cve-1", "pkg-1", "agent-1"],
      edges: [],
      composite_risk: 7.1,
      summary: "ordered labels",
      credential_exposure: [],
      tool_exposure: [],
      vuln_ids: ["CVE-2026-1212"],
    };

    const nodes = new Map<string, UnifiedNode>([
      [
        "cve-1",
        {
          id: "cve-1",
          entity_type: EntityType.VULNERABILITY,
          label: "CVE-2026-1212",
          category_uid: 2,
          class_uid: 2001,
          type_uid: 0,
          status: "active",
          risk_score: 9,
          severity: "critical",
          severity_id: 5,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "pkg-1",
        {
          id: "pkg-1",
          entity_type: EntityType.PACKAGE,
          label: "flask",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 5,
          severity: "medium",
          severity_id: 3,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "agent-1",
        {
          id: "agent-1",
          entity_type: EntityType.AGENT,
          label: "Claude Desktop",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
    ]);

    expect(attackPathSequenceLabels(path, nodes)).toEqual([
      "CVE-2026-1212",
      "flask",
      "Claude Desktop",
    ]);
  });

  it("recommends deterministic next actions for a selected path", () => {
    const path: AttackPath = {
      source: "cve-1",
      target: "agent-1",
      hops: ["cve-1", "agent-1"],
      edges: [],
      composite_risk: 9.2,
      summary: "actionable path",
      credential_exposure: ["ANTHROPIC_API_KEY"],
      tool_exposure: ["run_shell"],
      vuln_ids: ["CVE-2026-3434"],
    };

    const nodes = new Map<string, UnifiedNode>([
      [
        "cve-1",
        {
          id: "cve-1",
          entity_type: EntityType.VULNERABILITY,
          label: "CVE-2026-3434",
          category_uid: 2,
          class_uid: 2001,
          type_uid: 0,
          status: "active",
          risk_score: 9,
          severity: "critical",
          severity_id: 5,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
      [
        "agent-1",
        {
          id: "agent-1",
          entity_type: EntityType.AGENT,
          label: "Claude Desktop",
          category_uid: 5,
          class_uid: 4001,
          type_uid: 0,
          status: "active",
          risk_score: 6,
          severity: "high",
          severity_id: 4,
          first_seen: "2026-04-14T00:00:00Z",
          last_seen: "2026-04-14T00:00:00Z",
          attributes: {},
          compliance_tags: [],
          data_sources: [],
          dimensions: {},
        },
      ],
    ]);

    expect(recommendedAttackPathActions(path, nodes)).toEqual([
      {
        title: "Validate the lead finding",
        detail: "Open the primary CVE evidence first so the exploit chain has a confirmed root cause.",
        href: "/findings?cve=CVE-2026-3434",
      },
      {
        title: "Inspect the exposed agent",
        detail: "Review the first affected agent and confirm its connected servers, tools, and configuration trust boundary.",
        href: "/agents?name=Claude%20Desktop",
      },
      {
        title: "Contain credential exposure",
        detail: "Rotate or scope exposed secrets before you widen blast radius by exploring deeper topology.",
        href: "/mesh",
      },
    ]);
  });

  it("summarizes interaction risks for panel-level metrics", () => {
    expect(
      summarizeInteractionRisks([
        {
          pattern: "credential + tool",
          agents: ["Claude Desktop", "Cursor"],
          risk_score: 8.8,
          description: "shared exposure",
        },
        {
          pattern: "runtime drift",
          agents: ["Cursor"],
          risk_score: 6.4,
          description: "policy drift",
        },
      ]),
    ).toEqual({
      total: 2,
      uniqueAgents: 2,
      highestRisk: 8.8,
    });
  });

  it("recommends deterministic follow-up actions for an interaction risk", () => {
    expect(
      recommendedInteractionRiskActions({
        pattern: "credential + tool",
        agents: ["Claude Desktop"],
        risk_score: 8.2,
        description: "shared exposure",
        owasp_agentic_tag: "AGENT-001",
      }),
    ).toEqual([
      {
        label: "Open lead agent",
        href: "/agents?name=Claude%20Desktop",
      },
      {
        label: "Review tag evidence",
        href: "/compliance?q=AGENT-001",
      },
    ]);
  });
});
