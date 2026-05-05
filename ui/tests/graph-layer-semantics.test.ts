import { describe, expect, it } from "vitest";

import { GraphNodeKind, GRAPH_NODE_KIND_META } from "@/lib/graph-schema";

describe("graph semantic layers", () => {
  it("maps core security graph entities to operator-facing AI system layers", () => {
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.USER].layer).toBe("user");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.GROUP].layer).toBe("identity");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.SERVICE_ACCOUNT].layer).toBe("identity");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.CREDENTIAL].layer).toBe("identity");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.AGENT].layer).toBe("orchestration");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.SERVER].layer).toBe("mcp_server");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.TOOL].layer).toBe("tool");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.PACKAGE].layer).toBe("package");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.MODEL].layer).toBe("asset");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.DATASET].layer).toBe("asset");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.CONTAINER].layer).toBe("infra");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.CLOUD_RESOURCE].layer).toBe("infra");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.VULNERABILITY].layer).toBe("finding");
    expect(GRAPH_NODE_KIND_META[GraphNodeKind.MISCONFIGURATION].layer).toBe("finding");
  });
});
