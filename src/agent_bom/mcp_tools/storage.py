"""Lazy storage boundary shared by graph MCP tools."""


def default_graph_store():
    """Resolve configured storage lazily for MCP graph reads."""
    from agent_bom.api.stores import _get_graph_store

    return _get_graph_store()
