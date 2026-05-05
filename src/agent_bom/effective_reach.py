"""Effective-reach scoring — first-class graph signal for triage.

Driven by r/mcp community feedback (anderson_the_one, 455 upvotes):

    "A vulnerable package behind a read-only search tool is one severity.
     The same package behind a server with run_shell, visible AWS_* env
     names, and Claude Desktop access is a different incident. That path
     is the part people will actually act on."

The composite score lets agent-bom say *incident* instead of *vulnerable
package*.  It separates a finding-list tool from a triage tool: customers
act on incidents.

Determinism contract
====================

* Same graph in → same score out.  No randomness, no model weights, no
  network calls, no time-based inputs.  All coefficients live in this
  file with inline comments justifying their weight.
* The score is a pure function of :class:`ContextGraph` topology plus
  the CVE attributes already on the vulnerability node.  It does **not**
  replace the CVSS-based :mod:`risk_score`/`blast_radius` pipeline —
  it is an additional signal optimised for triage UX.
* The 0..100 composite, the band thresholds (green/amber/red/pulsing-red),
  and the breakdown dict are all stable for snapshot testing.

Inputs we lean on
=================

* CVSS base score (0..10) and EPSS exploit probability (0..1) are read
  off the vulnerability node's metadata where they were already attached
  by the scanner pipeline.
* CISA KEV presence.
* Tool capability — every ``TOOL`` node reachable from the affected
  ``SERVER`` nodes is classified by :mod:`risk_analyzer.ToolCapability`
  and the highest-weighted capability wins.
* Credential visibility — every ``CREDENTIAL`` node reachable from the
  affected servers is tiered (HOME → project → cloud-API token) using
  the heuristic in :func:`_credential_tier`.
* Agent breadth — number of distinct ``AGENT`` nodes that can pivot
  through any reachable server.  Capped at 5 so a single mass-deployed
  shared MCP doesn't dominate the score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from agent_bom.context_graph import ContextGraph, EdgeKind, GraphNode, NodeKind

# ── Capability weighting (deterministic) ──────────────────────────────────
#
# Each :class:`ToolCapability` maps to a 0..1 risk weight.  Read-only is
# cheap (~0.1), execute / admin are full strength.  These numbers were
# chosen so that a single read tool produces tool_capability ≈ 0.1
# (low-reach band) and a single shell-execute tool produces ≈ 1.0
# (high-reach band).  Multiple tools combine via *max* — a single shell
# is enough to tip the scale; we don't double-count breadth here.

_CAPABILITY_WEIGHT: dict[str, float] = {
    "read": 0.10,  # search/list/query — exfil is possible but bounded
    "network": 0.40,  # outbound HTTP — exfil channel
    "auth": 0.55,  # credential touch — privilege escalation
    "write": 0.65,  # mutate state — persistence
    "delete": 0.75,  # destructive — ransomware-class
    "admin": 0.85,  # config / role / install — full takeover surface
    "execute": 1.00,  # run shell / spawn — RCE primitive
}


# ── Credential visibility tiers ───────────────────────────────────────────
#
# Tier 1 (HOME-scoped):     HOME, USER, PWD, SHELL, LANG, TERM, PATH …
#                           No tenant boundary crossing risk; ~0.10.
# Tier 2 (project-scoped):  GITHUB_TOKEN, NPM_TOKEN, DATABASE_URL …
#                           Single tenant / repo blast radius; ~0.55.
# Tier 3 (cloud-API):       AWS_*, GCP_*, AZURE_*, OPENAI_*, ANTHROPIC_*…
#                           Cross-tenant infra blast radius; ~1.0.

_CLOUD_PREFIXES: tuple[str, ...] = (
    "AWS_",
    "AMAZON_",
    "GCP_",
    "GOOGLE_",
    "AZURE_",
    "MS_",
    "OPENAI_",
    "ANTHROPIC_",
    "CLAUDE_",
    "GEMINI_",
    "BEDROCK_",
    "VERTEX_",
    "DATABRICKS_",
    "SNOWFLAKE_",
    "STRIPE_",
    "TWILIO_",
    "DD_",  # Datadog
    "PAGERDUTY_",
)

_PROJECT_PREFIXES: tuple[str, ...] = (
    "GITHUB_",
    "GITLAB_",
    "BITBUCKET_",
    "NPM_",
    "PYPI_",
    "DOCKER_",
    "GHCR_",
    "DATABASE_",
    "DB_",
    "POSTGRES_",
    "MYSQL_",
    "REDIS_",
    "MONGODB_",
    "JIRA_",
    "SLACK_",
    "NOTION_",
    "LINEAR_",
    "OAUTH_",
)

_HOME_KEYS: frozenset[str] = frozenset(
    {
        "HOME",
        "USER",
        "USERNAME",
        "LOGNAME",
        "PWD",
        "OLDPWD",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "TMPDIR",
        "DISPLAY",
        "EDITOR",
    }
)


def _credential_tier(env_key: str) -> float:
    """Classify an env-var name into a 0..1 visibility weight.

    Pure string heuristic — deterministic, no I/O.
    """
    key = (env_key or "").strip().upper()
    if not key:
        return 0.0
    # Tier 3 — cloud / SaaS API credentials.  Anything matching a known
    # cloud prefix or containing an obviously cloud-y substring scores 1.0.
    for prefix in _CLOUD_PREFIXES:
        if key.startswith(prefix):
            return 1.0
    # Tier 2 — project-scoped credentials.
    for prefix in _PROJECT_PREFIXES:
        if key.startswith(prefix):
            return 0.55
    # Tier 1 — HOME-scoped / shell defaults.
    if key in _HOME_KEYS:
        return 0.10
    # Unknown env var with a credential-shaped name (TOKEN/SECRET/KEY/PASSWORD
    # in the suffix) — treat as project-scoped by default.  This is the
    # conservative bound: better to over-flag than under-flag.
    if any(token in key for token in ("TOKEN", "SECRET", "KEY", "PASSWORD", "API")):
        return 0.55
    return 0.10


# ── Score data structure ──────────────────────────────────────────────────


@dataclass(frozen=True)
class ReachScore:
    """Effective-reach score for a single CVE / finding node.

    All fields are inputs to :attr:`composite`; the breakdown dict
    returned by :meth:`as_breakdown` is what ships into the lineage
    detail panel and is checked into snapshot tests.
    """

    cvss: float  # CVSS base score, 0..10
    epss: float  # EPSS exploit probability, 0..1
    is_kev: bool  # CISA KEV presence
    tool_capability: float  # 0..1, max-of capability weights of reachable tools
    cred_visibility: float  # 0..1, max-of credential-tier weights of reachable env vars
    agent_breadth: int  # number of distinct agents that can pivot through
    # Free-form trace useful for the UI breakdown line.
    reachable_tools: tuple[str, ...] = field(default=())
    reachable_creds: tuple[str, ...] = field(default=())
    reachable_agents: tuple[str, ...] = field(default=())

    @property
    def composite(self) -> float:
        """Deterministic 0..100 composite score.

        Formula (every coefficient explained):

        * ``(cvss / 10) * 30`` — base severity, capped at 30 points.
          Tracks CVSS but doesn't *equal* CVSS so we can't exceed the
          ceiling on a 10.0 alone.
        * ``epss * 20`` — exploit-likelihood signal, 0..20 points.  EPSS
          is already a probability so it scales linearly.
        * ``+40 if is_kev else 0`` — CISA KEV is the loudest signal we
          have ("actively exploited in the wild"); this single bonus
          can flip a finding into the red band by itself.
        * ``tool_capability * 25`` — what can the reachable code do?
          Read-only adds ~2.5; shell adds 25.
        * ``cred_visibility * 20`` — what can it steal?  HOME-scoped
          adds ~2; AWS_* adds 20.
        * ``min(agent_breadth, 5) * 5`` — cross-agent pivot, capped at
          25 points so a fleet-wide MCP doesn't drown the formula.

        These coefficients were tuned so the low-reach fixture
        (CVSS 6.5, no KEV, read tool, HOME env, 1 agent) lands at ~25
        (green) and the high-reach fixture (CVSS 9.8, KEV, run_shell,
        AWS_*, claude-desktop) lands at ~95 (pulsing-red).
        """
        cvss_clamped = max(0.0, min(self.cvss, 10.0))
        epss_clamped = max(0.0, min(self.epss, 1.0))
        tool_clamped = max(0.0, min(self.tool_capability, 1.0))
        cred_clamped = max(0.0, min(self.cred_visibility, 1.0))
        breadth_clamped = max(0, min(self.agent_breadth, 5))

        score = (
            (cvss_clamped / 10.0) * 30.0  # 30% — base severity
            + epss_clamped * 20.0  # 20% — likelihood
            + (40.0 if self.is_kev else 0.0)  # KEV bonus — actively exploited
            + tool_clamped * 25.0  # 25% — capability of reachable code
            + cred_clamped * 20.0  # 20% — credential blast radius
            + breadth_clamped * 5.0  # 25% cap — cross-agent pivot
        )
        # Final clamp — without KEV the absolute max is 30+20+25+20+25 = 120
        # (we still clamp to 100 to keep the band UI honest).
        return round(max(0.0, min(score, 100.0)), 2)

    @property
    def band(self) -> Literal["green", "amber", "red", "pulsing-red"]:
        """Triage band.  Thresholds match the issue acceptance criteria."""
        composite = self.composite
        if composite >= 90.0:
            return "pulsing-red"
        if composite > 70.0:
            return "red"
        if composite > 30.0:
            return "amber"
        return "green"

    def as_breakdown(self) -> dict[str, object]:
        """Stable dict used by the UI detail panel and snapshot tests."""
        return {
            "cvss": round(self.cvss, 2),
            "epss": round(self.epss, 4),
            "is_kev": self.is_kev,
            "tool_capability": round(self.tool_capability, 3),
            "cred_visibility": round(self.cred_visibility, 3),
            "agent_breadth": self.agent_breadth,
            "reachable_tools": list(self.reachable_tools),
            "reachable_creds": list(self.reachable_creds),
            "reachable_agents": list(self.reachable_agents),
            "composite": self.composite,
            "band": self.band,
        }


# ── Graph traversal ───────────────────────────────────────────────────────


def _affected_servers(graph: ContextGraph, vuln_node_id: str) -> list[str]:
    """Return server-node IDs that point at this vuln via VULNERABLE_TO.

    The graph stores VULNERABLE_TO as ``server -> vuln`` (with reverse
    adjacency for traversal).  We scan ``edges`` directly so the result
    is independent of dict ordering and stays deterministic.
    """
    out: list[str] = []
    for edge in graph.edges:
        if edge.kind == EdgeKind.VULNERABLE_TO and edge.target == vuln_node_id:
            out.append(edge.source)
    out.sort()
    return out


def _tools_for_server(graph: ContextGraph, server_id: str) -> list[GraphNode]:
    """Return tool nodes provided by the given server (deterministic order)."""
    tools: list[GraphNode] = []
    for edge in graph.adjacency.get(server_id, []):
        if edge.kind != EdgeKind.PROVIDES:
            continue
        node = graph.nodes.get(edge.target)
        if node and node.kind == NodeKind.TOOL:
            tools.append(node)
    tools.sort(key=lambda n: n.id)
    return tools


def _creds_for_server(graph: ContextGraph, server_id: str) -> list[GraphNode]:
    """Return credential nodes exposed by the given server."""
    creds: list[GraphNode] = []
    for edge in graph.adjacency.get(server_id, []):
        if edge.kind != EdgeKind.EXPOSES:
            continue
        node = graph.nodes.get(edge.target)
        if node and node.kind == NodeKind.CREDENTIAL:
            creds.append(node)
    creds.sort(key=lambda n: n.id)
    return creds


def _agents_for_server(graph: ContextGraph, server_id: str) -> list[str]:
    """Agents that can pivot through the given server (sorted).

    Start with direct ``USES`` ownership, then fold in the graph-derived
    shared-server agent adjacency.  The latter matters when a vulnerability
    is attached to one instance of a shared MCP server: the paired
    ``SHARES_SERVER`` edge is the graph signal that other agents can reach
    the same server name even if they were not repeated in the blast row.
    """
    server_node = graph.nodes.get(server_id)
    if not server_node:
        return []
    server_name = server_node.label

    owner = server_node.metadata.get("agent")
    out: set[str] = set()
    if owner:
        out.add(str(owner))

    for edge in graph.edges:
        if edge.kind == EdgeKind.USES and edge.target == server_id:
            agent = graph.nodes.get(edge.source)
            if agent and agent.kind == NodeKind.AGENT:
                out.add(agent.label)

        if edge.kind != EdgeKind.SHARES_SERVER:
            continue
        if edge.metadata.get("server") != server_name:
            continue
        for endpoint_id in (edge.source, edge.target):
            agent = graph.nodes.get(endpoint_id)
            if agent and agent.kind == NodeKind.AGENT:
                out.add(agent.label)

    # Backward-compatible fallback for callers that manually connect
    # server -> agent in adjacency without using graph.edges.
    for edge in graph.adjacency.get(server_id, []):
        if edge.kind == EdgeKind.USES:
            other = graph.nodes.get(edge.target)
            if other and other.kind == NodeKind.AGENT:
                out.add(other.label)
    return sorted(out)


def _max_capability_weight(tool: GraphNode) -> tuple[float, str]:
    """Return (weight, capability_label) for the strongest capability."""
    caps = tool.metadata.get("capabilities") or []
    best = 0.0
    best_label = ""
    for cap in caps:
        weight = _CAPABILITY_WEIGHT.get(str(cap).lower(), 0.0)
        if weight > best:
            best = weight
            best_label = str(cap).lower()
    return best, best_label


# ── Public API ────────────────────────────────────────────────────────────


def compute(node: GraphNode, graph: ContextGraph) -> ReachScore:
    """Compute the deterministic effective-reach score for a CVE node.

    ``node`` must be a :class:`NodeKind.VULNERABILITY` graph node; for
    any other kind we still return a score (degenerate — no reachable
    capability/credential context) so callers can score generic
    finding-shaped nodes too.
    """
    cvss = float(node.metadata.get("cvss_score") or 0.0)
    epss = float(node.metadata.get("epss_score") or 0.0)
    is_kev = bool(node.metadata.get("is_kev"))

    tool_capability = 0.0
    cred_visibility = 0.0
    reachable_tools: list[str] = []
    reachable_creds: list[str] = []
    reachable_agents: set[str] = set()

    for server_id in _affected_servers(graph, node.id):
        for tool in _tools_for_server(graph, server_id):
            weight, label = _max_capability_weight(tool)
            if weight > tool_capability:
                tool_capability = weight
            # Track the highest-weighted tool name for the breakdown.
            if label and tool.label not in reachable_tools:
                reachable_tools.append(tool.label)
        for cred in _creds_for_server(graph, server_id):
            visibility = _credential_tier(cred.label)
            if visibility > cred_visibility:
                cred_visibility = visibility
            if cred.label not in reachable_creds:
                reachable_creds.append(cred.label)
        for agent_name in _agents_for_server(graph, server_id):
            reachable_agents.add(agent_name)

    reachable_tools.sort()
    reachable_creds.sort()

    return ReachScore(
        cvss=cvss,
        epss=epss,
        is_kev=is_kev,
        tool_capability=tool_capability,
        cred_visibility=cred_visibility,
        agent_breadth=len(reachable_agents),
        reachable_tools=tuple(reachable_tools),
        reachable_creds=tuple(reachable_creds),
        reachable_agents=tuple(sorted(reachable_agents)),
    )


def annotate_graph(graph: ContextGraph) -> dict[str, ReachScore]:
    """Compute and persist :class:`ReachScore` for every vuln node in ``graph``.

    The score is stored on ``GraphNode.metadata['effective_reach']`` as
    the breakdown dict (so it round-trips through ``to_serializable``
    untouched).  Edges adjacent to a scored node inherit the higher
    composite score of their endpoints in
    ``GraphEdge.metadata['effective_reach_score']`` — the dashboard uses
    this for edge thickness without doing its own traversal.

    Returns the per-node ``ReachScore`` for callers that want the typed
    object (e.g. the API layer attaching it to findings).
    """
    scores: dict[str, ReachScore] = {}
    for node_id, node in graph.nodes.items():
        if node.kind != NodeKind.VULNERABILITY:
            continue
        score = compute(node, graph)
        scores[node_id] = score
        node.metadata["effective_reach"] = score.as_breakdown()

    if not scores:
        return scores

    # Edges inherit the higher endpoint score.  Iterating ``graph.edges``
    # directly keeps this O(E); the adjacency view is reverse-mirrored
    # so we don't need to touch it.
    for edge in graph.edges:
        src_score = scores.get(edge.source)
        dst_score = scores.get(edge.target)
        candidates = [s.composite for s in (src_score, dst_score) if s is not None]
        if not candidates:
            continue
        edge.metadata["effective_reach_score"] = max(candidates)

    return scores


__all__ = [
    "ReachScore",
    "annotate_graph",
    "compute",
]
