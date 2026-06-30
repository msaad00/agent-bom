"""Agent-to-agent (A2A) auth posture governance.

agent-bom already *authenticates* calling agents (``agent_identity`` reads the
MCP ``_meta.agent_identity`` token; the gateway/proxy bind policy via
``bound_agents``) and *models* delegation (``delegation_chain`` /
``transitive_agents`` / ``ACTED_AS``). This module closes the governance gap:
nobody was checking whether that inter-agent authentication is *weak*.

It is **reference-only**. agent-bom does not become an auth broker, does not
mint or exchange tokens, and never emits secret values. It inspects discovered
agents, gateway/proxy policies, and delegation chains and flags four classes of
weakness as unified :class:`~agent_bom.finding.Finding` objects:

1. **Long-lived / shared credentials between agents** — one static token (or a
   credential env var) feeding multiple agents, violating short-lived-token
   policy.
2. **Missing mutual auth** — an agent-to-agent or agent-to-MCP edge with no
   verified caller identity (``require_agent_identity`` off) or no
   ``bound_agents`` restriction (wildcard / unbounded delegation).
3. **Over-broad delegation scope** — ``bound_agents`` allowing far more agents
   than needed, or unbounded transitive delegation depth.
4. **Unverified actor / on-behalf-of tokens** — delegation that crosses a trust
   boundary without a verifiable (signed/JWKS, RFC 8693-style) actor token.

Findings reuse :class:`FindingType.PROMPT_SECURITY` (the closest existing
agentic runtime-security bucket) and the ``owasp_agentic`` / ``owasp_mcp``
compliance tags. An optional graph overlay (:func:`annotate_graph_a2a_auth`)
flags the relevant agent/identity nodes and records ``InteractionRisk`` entries
using only existing entity/relationship types.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agent_bom.config import (
    A2A_AUTH_MAX_BOUND_AGENTS,
    A2A_AUTH_MAX_DELEGATION_DEPTH,
    A2A_AUTH_REQUIRE_SIGNED_TOKENS,
    A2A_AUTH_SHARED_TOKEN_MIN_AGENTS,
)
from agent_bom.finding import Asset, Finding, FindingSource, FindingType

if TYPE_CHECKING:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.models import Agent


# Wildcard tokens that mean "any agent" in a bound_agents list.
_WILDCARD_TOKENS = frozenset({"*", "any", "all", "wildcard"})

# OWASP Agentic / MCP control codes for the A2A auth weakness classes.
# ASI03 = Privilege Compromise, ASI04 = Identity & Impersonation,
# MCP01 = unauthenticated access, MCP09 = excessive trust/delegation.
_A2A_OWASP_AGENTIC = ["ASI03", "ASI04"]
_A2A_OWASP_MCP = ["MCP01", "MCP09"]


@dataclass
class A2APolicyView:
    """Normalized, transport-agnostic view of one gateway/proxy policy.

    Accepts either ``GatewayPolicy`` model instances, raw control-plane policy
    dicts, or per-MCP proxy policy dicts. Only the fields relevant to A2A auth
    governance are read; everything else is ignored.
    """

    policy_id: str = ""
    bound_agents: list[str] = field(default_factory=list)
    bound_agent_types: list[str] = field(default_factory=list)
    bound_environments: list[str] = field(default_factory=list)
    agent_tokens: dict[str, str] = field(default_factory=dict)
    require_agent_identity: bool = False
    has_signature_verification: bool = False
    jwks_uri: str = ""
    oidc_issuer: str = ""

    @property
    def is_unbounded(self) -> bool:
        """True when the policy binds no agents (or binds the wildcard)."""
        if not self.bound_agents:
            return True
        return any(a.strip().lower() in _WILDCARD_TOKENS for a in self.bound_agents)


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def normalize_policy(policy: Any) -> A2APolicyView:
    """Coerce a GatewayPolicy / dict into an :class:`A2APolicyView`."""

    def get(key: str, default: Any = None) -> Any:
        if isinstance(policy, dict):
            return policy.get(key, default)
        return getattr(policy, key, default)

    agent_tokens_raw = get("agent_tokens", {}) or {}
    agent_tokens = {str(k): str(v) for k, v in agent_tokens_raw.items()} if isinstance(agent_tokens_raw, dict) else {}

    jwks_uri = str(get("jwks_uri", "") or "")
    oidc_issuer = str(get("oidc_issuer", "") or "")

    return A2APolicyView(
        policy_id=str(get("policy_id", get("id", "")) or ""),
        bound_agents=_as_str_list(get("bound_agents", [])),
        bound_agent_types=_as_str_list(get("bound_agent_types", [])),
        bound_environments=_as_str_list(get("bound_environments", [])),
        agent_tokens=agent_tokens,
        require_agent_identity=bool(get("require_agent_identity", False)),
        has_signature_verification=bool(jwks_uri or oidc_issuer),
        jwks_uri=jwks_uri,
        oidc_issuer=oidc_issuer,
    )


# ── Delegation-chain helpers ─────────────────────────────────────────────────


def _split_chain(chain: Any) -> list[str]:
    """Split a delegation-chain entry into ordered hop labels.

    Chains are stored as arrow-joined strings (``"agent1→server2→agent2"``) or
    already-split lists. Returns the de-arrowed hop labels.
    """
    if isinstance(chain, (list, tuple)):
        hops: list[str] = []
        for part in chain:
            hops.extend(_split_chain(part))
        return hops
    if isinstance(chain, str):
        normalized = chain.replace("->", "→")
        return [hop.strip() for hop in normalized.split("→") if hop.strip()]
    return []


def _agent_delegation_chains(agent: Agent) -> list[list[str]]:
    """Return delegation chains declared on an agent's metadata.

    Discovery records delegation under ``metadata.delegation_chains`` (list of
    chains) or ``metadata.delegation_chain`` (single chain), with hops either
    arrow-joined or as lists. ``parent_agent`` contributes an implicit 1-hop
    chain so a simple parent→child spawn is still considered.
    """
    meta = agent.metadata if isinstance(agent.metadata, dict) else {}
    chains: list[list[str]] = []
    raw_chains = meta.get("delegation_chains")
    if isinstance(raw_chains, (list, tuple)):
        for entry in raw_chains:
            hops = _split_chain(entry)
            if hops:
                chains.append(hops)
    single = meta.get("delegation_chain")
    if single is not None:
        hops = _split_chain(single)
        if hops:
            chains.append(hops)
    if agent.parent_agent:
        chains.append([str(agent.parent_agent), agent.name])
    return chains


def _crosses_trust_boundary(agent: Agent, hops: list[str]) -> bool:
    """Heuristic: a chain crosses a trust boundary when hops span environments.

    ``metadata.environment`` / ``metadata.trust_domain`` on the agent, plus a
    ``metadata.delegation_environments`` map (hop label → environment), let the
    evaluator tell intra-domain delegation from cross-domain. When no boundary
    information is present we treat a multi-hop chain conservatively as crossing
    a boundary so unverified on-behalf-of tokens are not silently accepted.
    """
    meta = agent.metadata if isinstance(agent.metadata, dict) else {}
    env_map = meta.get("delegation_environments")
    if isinstance(env_map, dict):
        envs = {str(env_map.get(hop, "")).strip().lower() for hop in hops}
        envs.discard("")
        if len(envs) > 1:
            return True
        if envs:
            return False
    # No explicit per-hop environment data: a chain longer than a single
    # parent→child hop is conservatively treated as boundary-crossing.
    return len(hops) > 2


def _has_verifiable_actor_token(agent: Agent) -> bool:
    """Whether an agent declares a verifiable (signed/exchanged) actor token.

    Reference-only: we look for declared *posture* metadata, never token values.
    ``metadata.actor_token`` may carry ``{"verified": bool, "type": "jwt"|...}``
    or ``metadata.token_exchange``/``metadata.signed_delegation`` booleans.
    """
    meta = agent.metadata if isinstance(agent.metadata, dict) else {}
    actor = meta.get("actor_token")
    if isinstance(actor, dict) and bool(actor.get("verified")):
        return True
    if isinstance(actor, str) and actor.strip().lower() in {"verified", "signed", "jwt"}:
        return True
    return bool(meta.get("token_exchange") or meta.get("signed_delegation"))


# ── Weakness detectors ───────────────────────────────────────────────────────


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

    evidence = {"a2a_weakness": weakness, **evidence}
    finding = Finding(
        finding_type=FindingType.PROMPT_SECURITY,
        source=FindingSource.MCP_SCAN,
        asset=asset,
        severity=severity,
        title=title,
        description=description,
        remediation_guidance=remediation,
        owasp_agentic_tags=list(_A2A_OWASP_AGENTIC),
        owasp_mcp_tags=list(_A2A_OWASP_MCP),
        evidence=evidence,
        risk_score=risk_score,
    )
    return apply_hub_classification(finding)


def _agent_asset(agent: Agent) -> Asset:
    return Asset(name=agent.name, asset_type="agent", identifier=agent.canonical_id, location=agent.config_path or None)


def _detect_shared_credentials(agents: list[Agent], policies: list[A2APolicyView]) -> list[Finding]:
    """Weakness 1: long-lived / shared credentials between agents."""
    findings: list[Finding] = []

    # 1a. One opaque gateway/proxy token mapped to multiple agent_ids.
    token_to_agents: dict[str, set[str]] = defaultdict(set)
    token_policy: dict[str, str] = {}
    for pol in policies:
        for token, agent_id in pol.agent_tokens.items():
            token_to_agents[token].add(agent_id)
            token_policy[token] = pol.policy_id
    for idx, (token, agent_ids) in enumerate(sorted(token_to_agents.items())):
        if len(agent_ids) >= A2A_AUTH_SHARED_TOKEN_MIN_AGENTS:
            findings.append(
                _finding(
                    title="Shared static token authenticates multiple agents",
                    description=(
                        f"A single opaque gateway token authenticates {len(agent_ids)} distinct agents "
                        f"({', '.join(sorted(agent_ids))}). Shared long-lived tokens prevent per-agent "
                        "revocation and violate short-lived-token policy. Issue a distinct short-lived "
                        "credential per agent (or migrate to per-agent JWT/JWKS identity)."
                    ),
                    severity="high",
                    asset=Asset(
                        name=f"gateway-policy:{token_policy.get(token, '')}" or "gateway-policy",
                        asset_type="agent",
                        identifier=f"a2a:shared-token:{idx}",
                    ),
                    evidence={
                        "shared_agent_ids": sorted(agent_ids),
                        "agent_count": len(agent_ids),
                        "policy_id": token_policy.get(token, ""),
                    },
                    remediation="Issue a unique short-lived credential per agent; never map one static token to many agents.",
                    risk_score=7.5,
                    weakness="shared_credentials",
                )
            )

    # 1b. The same credential env-var name feeding multiple agents' servers.
    cred_to_agents: dict[str, set[str]] = defaultdict(set)
    for agent in agents:
        for server in agent.mcp_servers:
            for cred in server.credential_names:
                cred_to_agents[cred].add(agent.name)
    for cred, agent_names in sorted(cred_to_agents.items()):
        if len(agent_names) >= A2A_AUTH_SHARED_TOKEN_MIN_AGENTS:
            findings.append(
                _finding(
                    title="Shared credential referenced across multiple agents",
                    description=(
                        f"Credential env var {cred!r} is referenced by {len(agent_names)} agents "
                        f"({', '.join(sorted(agent_names))}). A credential shared across agents cannot be "
                        "rotated or revoked per agent and widens the blast radius of any single compromise."
                    ),
                    severity="medium",
                    asset=Asset(name=cred, asset_type="agent", identifier=f"a2a:shared-cred:{cred}"),
                    evidence={"credential_ref": cred, "agents": sorted(agent_names), "agent_count": len(agent_names)},
                    remediation="Scope each credential to a single agent identity and rotate on a short interval.",
                    risk_score=5.5,
                    weakness="shared_credentials",
                )
            )

    return findings


def _detect_missing_mutual_auth(agents: list[Agent], policies: list[A2APolicyView]) -> list[Finding]:
    """Weakness 2: missing mutual auth (no verified identity / unbounded binding)."""
    findings: list[Finding] = []

    identity_required = any(p.require_agent_identity for p in policies)
    has_any_policy = bool(policies)

    for agent in agents:
        # An agent that delegates onward (has child/transitive edges) but sits
        # behind no policy that requires caller identity has no mutual auth on
        # its agent-to-agent / agent-to-MCP edges.
        chains = _agent_delegation_chains(agent)
        network_servers = [s for s in agent.mcp_servers if s.url]
        delegates = bool(chains) or bool(agent.parent_agent)
        if not delegates and not network_servers:
            continue
        if has_any_policy and identity_required:
            continue
        reason = (
            "no gateway/proxy policy requires verified caller identity (require_agent_identity is off)"
            if has_any_policy
            else "no gateway/proxy policy governs this agent's inter-agent calls"
        )
        findings.append(
            _finding(
                title="Missing mutual authentication on inter-agent edges",
                description=(
                    f"Agent {agent.name!r} participates in agent-to-agent or agent-to-MCP communication but "
                    f"{reason}. Without a verified caller identity, a downstream agent or MCP server cannot "
                    "confirm who is calling it (no mutual auth)."
                ),
                severity="high",
                asset=_agent_asset(agent),
                evidence={
                    "agent": agent.name,
                    "delegation_chains": chains,
                    "network_servers": [s.name for s in network_servers],
                    "require_agent_identity": identity_required,
                },
                remediation="Bind a gateway policy with require_agent_identity=true (JWT/JWKS) to this agent's edges.",
                risk_score=7.0,
                weakness="missing_mutual_auth",
            )
        )

    # Unbounded / wildcard bindings: a policy that authorizes any agent has no
    # mutual-auth restriction on the calling side.
    for pol in policies:
        if pol.is_unbounded and not pol.require_agent_identity:
            findings.append(
                _finding(
                    title="Unbounded gateway policy accepts any calling agent",
                    description=(
                        f"Gateway policy {pol.policy_id!r} binds no specific agents "
                        f"({pol.bound_agents or 'empty'}) and does not require agent identity, so any agent "
                        "can invoke the governed tools. This is equivalent to a wildcard delegation grant."
                    ),
                    severity="high",
                    asset=Asset(
                        name=f"gateway-policy:{pol.policy_id}",
                        asset_type="agent",
                        identifier=f"a2a:unbounded-policy:{pol.policy_id}",
                    ),
                    evidence={
                        "policy_id": pol.policy_id,
                        "bound_agents": pol.bound_agents,
                        "require_agent_identity": pol.require_agent_identity,
                    },
                    remediation="Restrict bound_agents to the explicit caller set and require verified agent identity.",
                    risk_score=7.0,
                    weakness="missing_mutual_auth",
                )
            )

    return findings


def _detect_overbroad_delegation(agents: list[Agent], policies: list[A2APolicyView]) -> list[Finding]:
    """Weakness 3: over-broad delegation scope / unbounded transitive depth."""
    findings: list[Finding] = []

    for pol in policies:
        n = len(pol.bound_agents)
        if not pol.is_unbounded and n > A2A_AUTH_MAX_BOUND_AGENTS:
            findings.append(
                _finding(
                    title="Over-broad delegation scope in gateway policy",
                    description=(
                        f"Gateway policy {pol.policy_id!r} binds {n} agents, exceeding the configured "
                        f"maximum of {A2A_AUTH_MAX_BOUND_AGENTS}. Broad bound_agents lists grant far more "
                        "delegation reach than a least-privilege A2A posture allows."
                    ),
                    severity="medium",
                    asset=Asset(
                        name=f"gateway-policy:{pol.policy_id}",
                        asset_type="agent",
                        identifier=f"a2a:overbroad-policy:{pol.policy_id}",
                    ),
                    evidence={
                        "policy_id": pol.policy_id,
                        "bound_agent_count": n,
                        "max_bound_agents": A2A_AUTH_MAX_BOUND_AGENTS,
                    },
                    remediation="Split the policy per use case and bind only the agents that actually need each tool.",
                    risk_score=5.0,
                    weakness="overbroad_delegation",
                )
            )

    for agent in agents:
        for hops in _agent_delegation_chains(agent):
            depth = len(hops) - 1  # hops include the originating node
            if depth > A2A_AUTH_MAX_DELEGATION_DEPTH:
                findings.append(
                    _finding(
                        title="Unbounded transitive delegation depth",
                        description=(
                            f"Agent {agent.name!r} sits on a delegation chain {depth} hops deep "
                            f"(> {A2A_AUTH_MAX_DELEGATION_DEPTH}). Deep transitive delegation lets authority "
                            "propagate further than the originating grant intended."
                        ),
                        severity="medium",
                        asset=_agent_asset(agent),
                        evidence={
                            "agent": agent.name,
                            "delegation_depth": depth,
                            "max_delegation_depth": A2A_AUTH_MAX_DELEGATION_DEPTH,
                            "chain": hops,
                        },
                        remediation="Cap delegation depth and require re-authorization at trust-domain boundaries.",
                        risk_score=5.5,
                        weakness="overbroad_delegation",
                    )
                )

    return findings


def _detect_unverified_actor_tokens(agents: list[Agent], policies: list[A2APolicyView]) -> list[Finding]:
    """Weakness 4: unverified actor / on-behalf-of tokens crossing trust boundaries."""
    findings: list[Finding] = []
    if not A2A_AUTH_REQUIRE_SIGNED_TOKENS:
        return findings

    policy_verifies_signature = any(p.has_signature_verification for p in policies)

    for agent in agents:
        chains = _agent_delegation_chains(agent)
        boundary_chains = [hops for hops in chains if _crosses_trust_boundary(agent, hops)]
        if not boundary_chains:
            continue
        if _has_verifiable_actor_token(agent) or policy_verifies_signature:
            continue
        findings.append(
            _finding(
                title="Unverified on-behalf-of token across trust boundary",
                description=(
                    f"Agent {agent.name!r} delegates across a trust boundary without a verifiable actor token "
                    "(no signed/JWKS-backed RFC 8693-style token exchange, and no policy enforces signature "
                    "verification). A downstream service cannot cryptographically confirm the original actor."
                ),
                severity="high",
                asset=_agent_asset(agent),
                evidence={
                    "agent": agent.name,
                    "boundary_crossing_chains": boundary_chains,
                    "policy_verifies_signature": policy_verifies_signature,
                },
                remediation="Use RFC 8693 token exchange with signed actor tokens (JWKS) for cross-boundary delegation.",
                risk_score=7.5,
                weakness="unverified_actor_token",
            )
        )

    return findings


# ── Inline mutual-auth enforcement (assess → enforce) ─────────────────────────

# Enforcement modes for the inline A2A mutual-auth gate at the relay.
A2A_MUTUAL_AUTH_MODES = ("off", "warn", "enforce")

# Sentinel matching agent_bom.agent_identity.ANONYMOUS without importing it here.
ANONYMOUS_AGENT = "anonymous"


@dataclass
class InlineMutualAuthResult:
    """Classification of one inter-agent / agent-MCP edge for inline enforcement."""

    weak: bool
    reason: str = ""
    weakness: str = ""  # "invalid_identity" | "anonymous" | "unverified_identity"


def evaluate_inline_mutual_auth(
    *,
    source_agent: str,
    target: str,
    token_present: bool,
    verified: bool,
    identity_invalid_reason: str | None = None,
) -> InlineMutualAuthResult:
    """Classify whether one relayed edge carries mutual authentication.

    This is the inline, data-path counterpart to the reference-only posture
    scan above: instead of producing a finding, it tells the gateway relay
    whether the *current* call's caller→target edge is mutually authenticated so
    the relay can DENY (enforce) or flag (warn) a weak edge.

    An edge is weak when it does NOT carry a verified caller identity:
      * ``invalid_identity`` — a token was presented but is invalid/revoked/
        expired (``identity_invalid_reason`` set). Always weak.
      * ``anonymous`` — no identity token at all (the downstream agent/MCP
        cannot confirm who is calling).
      * ``unverified_identity`` — a token resolved to a concrete agent but was
        not cryptographically verified (opaque/shared/unsigned token, no
        JWKS/AS signature), so it is not mutual auth.

    Returns an :class:`InlineMutualAuthResult`; a verified, non-anonymous caller
    yields ``weak=False``. Pure + deterministic — no I/O, no token values.
    """
    edge = f"{source_agent or ANONYMOUS_AGENT} -> {target or 'mcp'}"
    if identity_invalid_reason:
        return InlineMutualAuthResult(
            weak=True,
            reason=f"edge {edge} presents an invalid/revoked identity ({identity_invalid_reason})",
            weakness="invalid_identity",
        )
    if not token_present or not source_agent or source_agent == ANONYMOUS_AGENT:
        return InlineMutualAuthResult(
            weak=True,
            reason=f"edge {edge} has no verified caller identity (anonymous); mutual auth is required",
            weakness="anonymous",
        )
    if not verified:
        return InlineMutualAuthResult(
            weak=True,
            reason=(f"edge {edge} presents an unverified (opaque/shared/unsigned) identity; a signed/JWKS-backed token is required"),
            weakness="unverified_identity",
        )
    return InlineMutualAuthResult(weak=False)


# ── Public entry points ──────────────────────────────────────────────────────


def evaluate_a2a_auth_posture(
    agents: list[Agent],
    *,
    gateway_policies: list[Any] | None = None,
    proxy_policies: list[Any] | None = None,
) -> list[Finding]:
    """Evaluate A2A auth posture and return weakness findings.

    Reference-only: inspects already-discovered agents and the supplied
    gateway/proxy policy bundles. Never authenticates, never emits secrets. A
    clean A2A configuration (per-agent identity, bounded policies, signed
    cross-boundary tokens) produces zero findings.
    """
    raw_policies: list[Any] = []
    raw_policies.extend(gateway_policies or [])
    raw_policies.extend(proxy_policies or [])
    policies = [normalize_policy(p) for p in raw_policies]

    findings: list[Finding] = []
    findings.extend(_detect_shared_credentials(agents, policies))
    findings.extend(_detect_missing_mutual_auth(agents, policies))
    findings.extend(_detect_overbroad_delegation(agents, policies))
    findings.extend(_detect_unverified_actor_tokens(agents, policies))
    return findings


# Map A2A weakness class → graph node-attribute flag (reuses existing nodes).
_WEAKNESS_ATTR = {
    "shared_credentials": "a2a_shared_credential",
    "missing_mutual_auth": "a2a_missing_mutual_auth",
    "overbroad_delegation": "a2a_overbroad_delegation",
    "unverified_actor_token": "a2a_unverified_actor_token",
}


def annotate_graph_a2a_auth_from_report(graph: UnifiedGraph, report_json: dict[str, Any]) -> dict[str, int]:
    """Annotate the graph from A2A findings already serialized in a report.

    Reads ``report_json["findings"]``, selects the PROMPT_SECURITY findings
    carrying an ``a2a_weakness`` evidence marker, and flags the matching
    agent/identity nodes. No-op when no A2A findings are present.
    """
    from agent_bom.graph.container import InteractionRisk
    from agent_bom.graph.types import EntityType

    raw_findings = report_json.get("findings")
    if not isinstance(raw_findings, list):
        return {"nodes_flagged": 0, "interaction_risks": 0}

    agent_nodes = {
        n.label: n
        for n in graph.nodes.values()
        if n.entity_type in (EntityType.AGENT, EntityType.MANAGED_IDENTITY, EntityType.FEDERATED_IDENTITY)
    }

    flagged = 0
    risks_added = 0
    for raw in raw_findings:
        if not isinstance(raw, dict) or raw.get("finding_type") != FindingType.PROMPT_SECURITY.value:
            continue
        raw_evidence = raw.get("evidence")
        evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
        weakness = str(evidence.get("a2a_weakness", ""))
        if not weakness:
            continue
        attr = _WEAKNESS_ATTR.get(weakness)
        raw_asset = raw.get("asset")
        asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
        agent_label = str(evidence.get("agent", "")) or str(asset.get("name", ""))
        node = agent_nodes.get(agent_label)
        if node is not None and attr:
            node.attributes[attr] = True
            node.attributes["a2a_auth_weak"] = True
            flagged += 1
        try:
            risk_score = min(10.0, max(0.0, float(raw.get("risk_score", 0.0) or 0.0)))
        except (TypeError, ValueError):
            risk_score = 0.0
        graph.interaction_risks.append(
            InteractionRisk(
                pattern=f"a2a_auth.{weakness}",
                agents=[agent_label] if agent_label else [],
                risk_score=risk_score,
                description=str(raw.get("title", "A2A auth weakness")),
                owasp_agentic_tag=_A2A_OWASP_AGENTIC[0],
            )
        )
        risks_added += 1

    return {"nodes_flagged": flagged, "interaction_risks": risks_added}


def annotate_graph_a2a_auth(graph: UnifiedGraph, findings: list[Finding]) -> dict[str, int]:
    """Flag agent/identity nodes named by A2A findings; record interaction risks.

    Reuses existing ``EntityType`` (AGENT / IDENTITY / MANAGED_IDENTITY) and
    ``InteractionRisk`` — invents no new graph types. Matches findings to nodes
    by agent label/name. Never raises into the builder.
    """
    from agent_bom.graph.container import InteractionRisk
    from agent_bom.graph.types import EntityType

    flagged = 0
    risks_added = 0
    agent_nodes = {
        n.label: n
        for n in graph.nodes.values()
        if n.entity_type in (EntityType.AGENT, EntityType.MANAGED_IDENTITY, EntityType.FEDERATED_IDENTITY)
    }

    for finding in findings:
        weakness = str(finding.evidence.get("a2a_weakness", ""))
        attr = _WEAKNESS_ATTR.get(weakness)
        agent_label = str(finding.evidence.get("agent", "")) or finding.asset.name
        node = agent_nodes.get(agent_label)
        if node is not None and attr:
            node.attributes[attr] = True
            node.attributes["a2a_auth_weak"] = True
            flagged += 1
        graph.interaction_risks.append(
            InteractionRisk(
                pattern=f"a2a_auth.{weakness}" if weakness else "a2a_auth",
                agents=[agent_label],
                risk_score=min(10.0, max(0.0, finding.risk_score)),
                description=finding.title,
                owasp_agentic_tag=_A2A_OWASP_AGENTIC[0],
            )
        )
        risks_added += 1

    return {"nodes_flagged": flagged, "interaction_risks": risks_added}
