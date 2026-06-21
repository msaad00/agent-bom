"""MCP server + agent→MCP auth posture governance.

This is the complement of :mod:`agent_bom.a2a_auth_posture`. That module covers
*inter-agent* (A2A) authentication. This module covers the **MCP SERVER auth**
surface and the **agent→MCP** edge, per the MCP authorization spec (OAuth 2.1
for remote MCP servers, 2025). Many MCP servers ship with **no auth**, and a
remote MCP reachable over the network with no token/OAuth is the single biggest
exposure on this surface.

It is **reference-only**. agent-bom does not become an auth broker, does not
mint or exchange tokens, and never emits secret values. It inspects already
discovered MCP servers, their transports/config, and any proxy ``bound_agents``
policies, and flags four classes of weakness as unified
:class:`~agent_bom.finding.Finding` objects:

1. **Unauthenticated MCP server** — a server reachable over SSE /
   streamable-HTTP / network transport that requires no auth (no token, no
   OAuth, no bound_agents). stdio-local is lower risk and is not flagged by
   default; network-with-no-auth is high.
2. **Missing / weak transport security** — a remote MCP reached over plaintext
   ``http://`` (no TLS), or credentials embedded directly in the URL.
3. **Over-broad / static MCP credentials** — long-lived static API keys in the
   MCP server env (ties to the no-passwords / short-lived-token policy) instead
   of short-lived OAuth access tokens.
4. **Agent→MCP auth gap** — an agent calling a network MCP server with no
   verified caller identity and no proxy ``bound_agents`` restriction governing
   that edge.

Findings reuse :class:`FindingType.PROMPT_SECURITY` (the closest existing
agentic runtime-security bucket; the same bucket the A2A evaluator uses) and the
``owasp_mcp`` compliance tags. An optional graph overlay
(:func:`annotate_graph_mcp_auth`) flags the relevant MCP-server nodes and
records ``InteractionRisk`` entries using only existing entity/relationship
types.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agent_bom.config import (
    MCP_AUTH_FLAG_LOCAL_STDIO,
    MCP_AUTH_REQUIRE_NETWORK_AUTH,
    MCP_AUTH_REQUIRE_TLS,
    MCP_AUTH_STATIC_CRED_ALLOWLIST,
)
from agent_bom.finding import Asset, Finding, FindingSource, FindingType

if TYPE_CHECKING:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.models import Agent, MCPServer

# Wildcard tokens that mean "any agent" in a bound_agents list.
_WILDCARD_TOKENS = frozenset({"*", "any", "all", "wildcard"})

# OWASP MCP control codes for the MCP-auth weakness classes.
# MCP01 = unauthenticated / broken access control, MCP04 = insecure
# transport / credential handling, MCP09 = excessive trust.
_MCP_AUTH_OWASP_MCP = ["MCP01", "MCP04"]
_MCP_AUTH_OWASP_AGENTIC = ["ASI04"]

# Env-var substrings that indicate a *short-lived* / OAuth-backed credential
# rather than a long-lived static API key. If a server only carries these, its
# credentials are not flagged as over-broad static secrets.
_SHORT_LIVED_CRED_HINTS = frozenset(
    {
        "oauth",
        "access_token",
        "refresh_token",
        "bearer",
        "id_token",
        "client_credentials",
        "session",
        "jwt",
    }
)

# Env-var substrings that strongly indicate a long-lived static secret.
_STATIC_CRED_HINTS = frozenset(
    {
        "api_key",
        "apikey",
        "secret_key",
        "access_key",
        "private_key",
        "password",
        "passwd",
        "client_secret",
        "service_account",
        "static_token",
    }
)


# ── Normalized views ─────────────────────────────────────────────────────────


@dataclass
class MCPProxyPolicyView:
    """Normalized view of one proxy / gateway policy as it governs MCP edges.

    Only the fields relevant to MCP-auth governance are read: which agents are
    bound, whether a verified caller identity is required, and which MCP server
    the policy scopes (when declared).
    """

    policy_id: str = ""
    server: str = ""
    bound_agents: list[str] = field(default_factory=list)
    require_agent_identity: bool = False

    @property
    def is_unbounded(self) -> bool:
        if not self.bound_agents:
            return True
        return any(a.strip().lower() in _WILDCARD_TOKENS for a in self.bound_agents)


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def normalize_proxy_policy(policy: Any) -> MCPProxyPolicyView:
    """Coerce a GatewayPolicy / proxy-policy dict into an MCPProxyPolicyView."""

    def get(key: str, default: Any = None) -> Any:
        if isinstance(policy, dict):
            return policy.get(key, default)
        return getattr(policy, key, default)

    return MCPProxyPolicyView(
        policy_id=str(get("policy_id", get("id", "")) or ""),
        server=str(get("server", get("mcp_server", get("upstream", ""))) or ""),
        bound_agents=_as_str_list(get("bound_agents", [])),
        require_agent_identity=bool(get("require_agent_identity", False)),
    )


# ── Server-level helpers ─────────────────────────────────────────────────────


def _is_network_transport(server: MCPServer) -> bool:
    """True when the server is reached over the network (SSE / HTTP / url)."""
    from agent_bom.models import TransportType

    if server.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP):
        return True
    return bool(server.url)


def _server_metadata(server: MCPServer) -> dict[str, Any]:
    """Best-effort auth posture metadata declared on the server.

    Discovery may stamp an ``auth`` posture dict onto a server's
    ``security_intelligence`` entries (reference-only, never secret values). We
    read declared *posture* booleans such as ``requires_auth`` / ``oauth`` /
    ``tls`` so an operator can assert auth on a server we cannot probe.
    """
    for entry in server.security_intelligence:
        if isinstance(entry, dict) and entry.get("kind") == "mcp_auth":
            return entry
    return {}


def _declares_auth(server: MCPServer) -> bool:
    """Whether the server declares (or carries config implying) required auth.

    Reference-only signals, in priority order:
      * an explicit ``mcp_auth`` posture entry with ``requires_auth``/``oauth``;
      * a credential env var the server presents to the *upstream* (bearer /
        OAuth / token) — i.e. ``auth_mode == "env-credentials"`` with an
        auth-shaped credential name, which means the server is configured to
        authenticate *to* something and is not a bare open endpoint.
    """
    meta = _server_metadata(server)
    if bool(meta.get("requires_auth")) or bool(meta.get("oauth")) or bool(meta.get("oidc")):
        return True
    # A server that carries an auth-shaped credential ref (bearer/token/oauth)
    # is configured with authentication material; treat it as authenticated.
    for cred in server.credential_names:
        low = cred.lower()
        if any(hint in low for hint in ("token", "bearer", "oauth", "auth", "key", "secret")):
            return True
    return False


def _has_tls(server: MCPServer) -> bool:
    """Whether the remote endpoint uses TLS (https / wss) or is non-network."""
    meta = _server_metadata(server)
    if "tls" in meta:
        return bool(meta.get("tls"))
    url = (server.url or "").strip().lower()
    if not url:
        return True  # stdio / no network endpoint: TLS is not applicable
    if url.startswith(("https://", "wss://")):
        return True
    if url.startswith(("http://", "ws://")):
        return False
    # Schemeless host:port reached over the network — conservatively no TLS.
    return False


def _url_has_embedded_credentials(server: MCPServer) -> bool:
    """True when credentials are embedded in the URL userinfo (user:pass@)."""
    url = (server.url or "").strip()
    if "@" not in url:
        return False
    # Only the authority component carries userinfo; ignore query-string '@'.
    after_scheme = url.split("://", 1)[-1]
    authority = after_scheme.split("/", 1)[0]
    return "@" in authority


def _static_credential_names(server: MCPServer) -> list[str]:
    """Return credential env-var names that look like long-lived static secrets.

    A credential is treated as static unless every credential the server carries
    is OAuth / short-lived-shaped. Allowlisted names (config) are excluded.
    """
    creds = server.credential_names
    if not creds:
        return []
    static: list[str] = []
    for cred in creds:
        low = cred.lower()
        if any(allow in low for allow in MCP_AUTH_STATIC_CRED_ALLOWLIST):
            continue
        if any(hint in low for hint in _SHORT_LIVED_CRED_HINTS):
            continue
        if any(hint in low for hint in _STATIC_CRED_HINTS):
            static.append(cred)
    return static


# ── Finding factory ──────────────────────────────────────────────────────────


def _finding(
    *,
    title: str,
    description: str,
    severity: str,
    asset: Asset,
    evidence: dict[str, Any],
    remediation: str,
    risk_score: float,
    weakness: str,
) -> Finding:
    from agent_bom.compliance_hub import apply_hub_classification

    evidence = {"mcp_auth_weakness": weakness, **evidence}
    finding = Finding(
        finding_type=FindingType.PROMPT_SECURITY,
        source=FindingSource.MCP_SCAN,
        asset=asset,
        severity=severity,
        title=title,
        description=description,
        remediation_guidance=remediation,
        owasp_mcp_tags=list(_MCP_AUTH_OWASP_MCP),
        owasp_agentic_tags=list(_MCP_AUTH_OWASP_AGENTIC),
        evidence=evidence,
        risk_score=risk_score,
    )
    return apply_hub_classification(finding)


def _server_asset(server: MCPServer) -> Asset:
    from agent_bom.security import sanitize_url

    location = sanitize_url(server.url) if server.url else (server.config_path or None)
    return Asset(name=server.name, asset_type="mcp_server", identifier=server.canonical_id, location=location)


# ── Weakness detectors ───────────────────────────────────────────────────────


def _iter_servers(agents: list[Agent]) -> list[tuple[Agent | None, MCPServer]]:
    """Flatten (agent, server) pairs, de-duplicating shared server instances."""
    seen: set[int] = set()
    pairs: list[tuple[Agent | None, MCPServer]] = []
    for agent in agents:
        for server in agent.mcp_servers:
            pairs.append((agent, server))
            seen.add(id(server))
    return pairs


def _detect_unauthenticated_server(pairs: list[tuple[Agent | None, MCPServer]]) -> list[Finding]:
    """Weakness 1: network-reachable MCP server with no auth required."""
    findings: list[Finding] = []
    if not MCP_AUTH_REQUIRE_NETWORK_AUTH:
        return findings

    emitted: set[str] = set()
    for _agent, server in pairs:
        if not server.is_mcp_surface or server.security_blocked:
            continue
        network = _is_network_transport(server)
        if not network and not (MCP_AUTH_FLAG_LOCAL_STDIO and server.credential_names):
            continue
        if not network:
            continue
        if _declares_auth(server):
            continue
        key = server.canonical_id
        if key in emitted:
            continue
        emitted.add(key)
        findings.append(
            _finding(
                title="Unauthenticated network-reachable MCP server",
                description=(
                    f"MCP server {server.name!r} is reachable over a network transport "
                    f"({server.transport.value}) but requires no authentication (no bearer token, OAuth, "
                    "or proxy binding observed). Per the MCP authorization spec, remote MCP servers must "
                    "require OAuth 2.1; an open network endpoint lets any caller invoke its tools."
                ),
                severity="high",
                asset=_server_asset(server),
                evidence={
                    "server": server.name,
                    "transport": server.transport.value,
                    "auth_mode": server.auth_mode,
                    "has_url": bool(server.url),
                },
                remediation=(
                    "Require OAuth 2.1 (or at minimum a verified bearer token) on the MCP server, or front it "
                    "with the agent-bom gateway/proxy and bind authorized agents via bound_agents."
                ),
                risk_score=8.0,
                weakness="unauthenticated_server",
            )
        )
    return findings


def _detect_weak_transport(pairs: list[tuple[Agent | None, MCPServer]]) -> list[Finding]:
    """Weakness 2: remote MCP over non-TLS, or credentials embedded in the URL."""
    findings: list[Finding] = []
    emitted_tls: set[str] = set()
    emitted_embed: set[str] = set()

    for _agent, server in pairs:
        if not server.is_mcp_surface or server.security_blocked:
            continue
        if not _is_network_transport(server):
            continue
        key = server.canonical_id

        if MCP_AUTH_REQUIRE_TLS and not _has_tls(server) and key not in emitted_tls:
            emitted_tls.add(key)
            findings.append(
                _finding(
                    title="Remote MCP server over non-TLS transport",
                    description=(
                        f"MCP server {server.name!r} is reached over a plaintext (non-TLS) network transport. "
                        "Tokens, tool arguments, and responses traverse the wire unencrypted and can be "
                        "intercepted or tampered with. The MCP authorization spec requires HTTPS for remote "
                        "servers."
                    ),
                    severity="high",
                    asset=_server_asset(server),
                    evidence={
                        "server": server.name,
                        "transport": server.transport.value,
                        "tls": False,
                    },
                    remediation="Serve the remote MCP endpoint over HTTPS/WSS (TLS) and reject plaintext connections.",
                    risk_score=7.0,
                    weakness="weak_transport",
                )
            )

        if _url_has_embedded_credentials(server) and key not in emitted_embed:
            emitted_embed.add(key)
            findings.append(
                _finding(
                    title="MCP server credentials embedded in connection URL",
                    description=(
                        f"MCP server {server.name!r} embeds credentials directly in its connection URL "
                        "(userinfo component). Such credentials are long-lived, leak through logs/history, and "
                        "cannot be rotated independently of the endpoint."
                    ),
                    severity="medium",
                    asset=_server_asset(server),
                    evidence={"server": server.name, "auth_mode": server.auth_mode},
                    remediation=(
                        "Move the credential out of the URL into a short-lived OAuth token presented via the "
                        "Authorization header; never put secrets in the URL."
                    ),
                    risk_score=5.5,
                    weakness="weak_transport",
                )
            )
    return findings


def _detect_static_credentials(pairs: list[tuple[Agent | None, MCPServer]]) -> list[Finding]:
    """Weakness 3: long-lived static MCP credentials instead of short-lived OAuth."""
    findings: list[Finding] = []
    emitted: set[str] = set()

    for _agent, server in pairs:
        if not server.is_mcp_surface or server.security_blocked:
            continue
        network = _is_network_transport(server)
        # Local stdio static creds are lower risk; only flagged when explicitly enabled.
        if not network and not MCP_AUTH_FLAG_LOCAL_STDIO:
            continue
        static = _static_credential_names(server)
        if not static:
            continue
        key = server.canonical_id
        if key in emitted:
            continue
        emitted.add(key)
        findings.append(
            _finding(
                title="Long-lived static credential on MCP server",
                description=(
                    f"MCP server {server.name!r} authenticates with long-lived static credential(s) "
                    f"({', '.join(sorted(static))}) rather than short-lived OAuth access tokens. Static API "
                    "keys cannot be rotated or revoked quickly and violate the short-lived-token policy."
                ),
                severity="medium",
                asset=_server_asset(server),
                evidence={
                    "server": server.name,
                    "static_credential_refs": sorted(static),
                    "transport": server.transport.value,
                    "auth_mode": server.auth_mode,
                },
                remediation=(
                    "Replace static API keys with short-lived OAuth 2.1 access tokens (refresh-on-expiry); scope "
                    "and rotate any remaining static secret on a short interval."
                ),
                risk_score=5.5,
                weakness="static_credentials",
            )
        )
    return findings


def _detect_agent_mcp_auth_gap(
    pairs: list[tuple[Agent | None, MCPServer]],
    policies: list[MCPProxyPolicyView],
) -> list[Finding]:
    """Weakness 4: agent→MCP edge with no verified identity / no bound_agents."""
    findings: list[Finding] = []

    # Index policies by the server they scope; unscoped policies apply globally.
    by_server: dict[str, list[MCPProxyPolicyView]] = defaultdict(list)
    global_policies: list[MCPProxyPolicyView] = []
    for pol in policies:
        if pol.server:
            by_server[pol.server].append(pol)
        else:
            global_policies.append(pol)

    def governing(server: MCPServer) -> list[MCPProxyPolicyView]:
        return by_server.get(server.name, []) + global_policies

    emitted: set[tuple[str, str]] = set()
    for agent, server in pairs:
        if agent is None or not server.is_mcp_surface or server.security_blocked:
            continue
        if not _is_network_transport(server):
            continue  # the agent→MCP gap matters for network edges
        govern = governing(server)
        # The edge is protected when some governing policy requires a verified
        # caller identity, is not wildcard-bound, and either names this agent or
        # is a server-scoped policy already matched to this server.
        protected = any(
            pol.require_agent_identity and not pol.is_unbounded and (agent.name in pol.bound_agents or not pol.server) for pol in govern
        )
        if protected:
            continue
        key = (agent.name, server.canonical_id)
        if key in emitted:
            continue
        emitted.add(key)
        if not govern:
            reason = "no proxy/gateway policy governs this agent→MCP edge (no bound_agents restriction)"
        elif not any(p.require_agent_identity for p in govern):
            reason = "the governing proxy policy does not require a verified caller identity"
        else:
            reason = "no governing proxy policy binds this agent (bound_agents is empty or wildcard)"
        findings.append(
            _finding(
                title="Agent calls MCP server without verified identity",
                description=(
                    f"Agent {agent.name!r} calls network MCP server {server.name!r}, but {reason}. The MCP server "
                    "cannot confirm which agent is invoking it, so any caller reaching the endpoint is "
                    "indistinguishable from this agent."
                ),
                severity="high",
                asset=_server_asset(server),
                evidence={
                    "agent": agent.name,
                    "server": server.name,
                    "transport": server.transport.value,
                    "governing_policy_ids": [p.policy_id for p in govern],
                },
                remediation=(
                    "Front the MCP server with the agent-bom gateway/proxy, bind the calling agent via "
                    "bound_agents, and require a verified agent identity (require_agent_identity / OAuth)."
                ),
                risk_score=7.0,
                weakness="agent_mcp_auth_gap",
            )
        )
    return findings


# ── Public entry points ──────────────────────────────────────────────────────


def evaluate_mcp_auth_posture(
    agents: list[Agent],
    *,
    proxy_policies: list[Any] | None = None,
    gateway_policies: list[Any] | None = None,
) -> list[Finding]:
    """Evaluate MCP server + agent→MCP auth posture and return weakness findings.

    Reference-only: inspects already-discovered agents/MCP servers and the
    supplied proxy/gateway policy bundles. Never authenticates, never emits
    secrets. A clean MCP configuration (network servers behind OAuth/TLS, bound
    agents, short-lived tokens) produces zero findings.
    """
    raw_policies: list[Any] = []
    raw_policies.extend(proxy_policies or [])
    raw_policies.extend(gateway_policies or [])
    policies = [normalize_proxy_policy(p) for p in raw_policies]

    pairs = _iter_servers(agents)

    findings: list[Finding] = []
    findings.extend(_detect_unauthenticated_server(pairs))
    findings.extend(_detect_weak_transport(pairs))
    findings.extend(_detect_static_credentials(pairs))
    findings.extend(_detect_agent_mcp_auth_gap(pairs, policies))
    return findings


# Map weakness class → graph node-attribute flag (reuses existing MCP nodes).
_WEAKNESS_ATTR = {
    "unauthenticated_server": "mcp_auth_unauthenticated",
    "weak_transport": "mcp_auth_weak_transport",
    "static_credentials": "mcp_auth_static_credentials",
    "agent_mcp_auth_gap": "mcp_auth_agent_gap",
}


def _flag_node(node: Any, weakness: str) -> bool:
    attr = _WEAKNESS_ATTR.get(weakness)
    if not attr:
        return False
    node.attributes[attr] = True
    node.attributes["mcp_auth_weak"] = True
    return True


def annotate_graph_mcp_auth_from_report(graph: UnifiedGraph, report_json: dict[str, Any]) -> dict[str, int]:
    """Annotate the graph from MCP-auth findings already serialized in a report.

    Reads ``report_json["findings"]``, selects PROMPT_SECURITY findings carrying
    an ``mcp_auth_weakness`` evidence marker, and flags the matching MCP-server
    nodes. No-op when no MCP-auth findings are present.
    """
    from agent_bom.graph.container import InteractionRisk
    from agent_bom.graph.types import EntityType

    raw_findings = report_json.get("findings")
    if not isinstance(raw_findings, list):
        return {"nodes_flagged": 0, "interaction_risks": 0}

    server_nodes = {n.label: n for n in graph.nodes.values() if n.entity_type == EntityType.SERVER}

    flagged = 0
    risks_added = 0
    for raw in raw_findings:
        if not isinstance(raw, dict) or raw.get("finding_type") != FindingType.PROMPT_SECURITY.value:
            continue
        raw_evidence = raw.get("evidence")
        evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
        weakness = str(evidence.get("mcp_auth_weakness", ""))
        if not weakness:
            continue
        raw_asset = raw.get("asset")
        asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
        server_label = str(evidence.get("server", "")) or str(asset.get("name", ""))
        node = server_nodes.get(server_label)
        if node is not None and _flag_node(node, weakness):
            flagged += 1
        try:
            risk_score = min(10.0, max(0.0, float(raw.get("risk_score", 0.0) or 0.0)))
        except (TypeError, ValueError):
            risk_score = 0.0
        graph.interaction_risks.append(
            InteractionRisk(
                pattern=f"mcp_auth.{weakness}",
                agents=[str(evidence.get("agent", ""))] if evidence.get("agent") else [],
                risk_score=risk_score,
                description=str(raw.get("title", "MCP auth weakness")),
                owasp_agentic_tag=_MCP_AUTH_OWASP_AGENTIC[0],
            )
        )
        risks_added += 1

    return {"nodes_flagged": flagged, "interaction_risks": risks_added}


def annotate_graph_mcp_auth(graph: UnifiedGraph, findings: list[Finding]) -> dict[str, int]:
    """Flag MCP-server nodes named by MCP-auth findings; record interaction risks.

    Reuses existing ``EntityType.SERVER`` and ``InteractionRisk`` — invents
    no new graph types. Matches findings to nodes by server label/name. Never
    raises into the builder.
    """
    from agent_bom.graph.container import InteractionRisk
    from agent_bom.graph.types import EntityType

    flagged = 0
    risks_added = 0
    server_nodes = {n.label: n for n in graph.nodes.values() if n.entity_type == EntityType.SERVER}

    for finding in findings:
        weakness = str(finding.evidence.get("mcp_auth_weakness", ""))
        server_label = str(finding.evidence.get("server", "")) or finding.asset.name
        node = server_nodes.get(server_label)
        if node is not None and _flag_node(node, weakness):
            flagged += 1
        graph.interaction_risks.append(
            InteractionRisk(
                pattern=f"mcp_auth.{weakness}" if weakness else "mcp_auth",
                agents=[str(finding.evidence.get("agent", ""))] if finding.evidence.get("agent") else [],
                risk_score=min(10.0, max(0.0, finding.risk_score)),
                description=finding.title,
                owasp_agentic_tag=_MCP_AUTH_OWASP_AGENTIC[0],
            )
        )
        risks_added += 1

    return {"nodes_flagged": flagged, "interaction_risks": risks_added}
