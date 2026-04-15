"""Blast-radius expansion helpers for scanner results."""

from __future__ import annotations

from agent_bom.models import Agent, BlastRadius

_HOP_RISK_FACTORS: dict[int, float] = {
    1: 1.0,
    2: 0.7,
    3: 0.5,
    4: 0.35,
    5: 0.25,
}


def expand_blast_radius_hops(
    blast_radii: list[BlastRadius],
    agents: list[Agent],
    max_depth: int = 1,
) -> None:
    """Expand blast radii with multi-hop delegation chain analysis."""
    max_depth = max(1, min(max_depth, 5))
    if max_depth <= 1:
        return

    server_to_agents: dict[str, list[Agent]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            server_to_agents.setdefault(server.name, []).append(agent)

    agent_to_servers: dict[str, list[str]] = {}
    for agent in agents:
        agent_to_servers[agent.name] = [server.name for server in agent.mcp_servers]

    for blast_radius in blast_radii:
        direct_agent_names = {agent.name for agent in blast_radius.affected_agents}
        direct_server_names = {server.name for server in blast_radius.affected_servers}

        visited_agents: set[str] = set(direct_agent_names)
        visited_servers: set[str] = set(direct_server_names)
        transitive_agents: list[dict] = []
        transitive_credentials: list[str] = []
        chains: list[str] = []

        queue: list[tuple[str, int, list[str]]] = []
        for agent in blast_radius.affected_agents:
            for server_name in agent_to_servers.get(agent.name, []):
                if server_name not in direct_server_names:
                    queue.append((agent.name, 1, [agent.name, server_name]))
                    visited_servers.add(server_name)

        max_hop_reached = 1
        while queue:
            _agent_name, hop, chain = queue.pop(0)
            if hop >= max_depth:
                continue

            current_server = chain[-1]
            for next_agent in server_to_agents.get(current_server, []):
                if next_agent.name in visited_agents:
                    continue
                visited_agents.add(next_agent.name)
                next_hop = hop + 1
                max_hop_reached = max(max_hop_reached, next_hop)

                new_chain = chain + [next_agent.name]
                chain_str = "\u2192".join(new_chain)
                chains.append(chain_str)

                agent_creds: list[str] = []
                for server in next_agent.mcp_servers:
                    agent_creds.extend(server.credential_names)
                agent_creds = list(set(agent_creds))

                transitive_agents.append(
                    {
                        "name": next_agent.name,
                        "type": next_agent.agent_type.value,
                        "hop": next_hop,
                        "chain": chain_str,
                    }
                )
                transitive_credentials.extend(agent_creds)

                if next_hop < max_depth:
                    for server_name in agent_to_servers.get(next_agent.name, []):
                        if server_name not in visited_servers:
                            visited_servers.add(server_name)
                            queue.append((next_agent.name, next_hop, new_chain + [server_name]))

        if transitive_agents:
            blast_radius.hop_depth = max_hop_reached
            blast_radius.delegation_chain = chains
            blast_radius.transitive_agents = transitive_agents
            blast_radius.transitive_credentials = list(set(transitive_credentials))
            factor = _HOP_RISK_FACTORS.get(max_hop_reached, 0.25)
            blast_radius.transitive_risk_score = round(blast_radius.risk_score * factor, 2)
