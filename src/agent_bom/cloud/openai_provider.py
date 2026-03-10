"""OpenAI platform discovery — assistants, fine-tuned models, and files.

Requires ``openai``.  Install with::

    pip install 'agent-bom[openai]'

Authentication uses OPENAI_API_KEY env var or --openai-api-key flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    api_key: str | None = None,
    organization: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI assets from the OpenAI platform.

    Discovers Assistants (with tools and files), fine-tuned models,
    and training files.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``openai`` is not installed.
    """
    try:
        import openai  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("openai is required for OpenAI discovery. Install with: pip install 'agent-bom[openai]'")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    resolved_org = organization or os.environ.get("OPENAI_ORG_ID", "")

    if not resolved_key:
        warnings.append("OPENAI_API_KEY not set. Provide --openai-api-key or set the OPENAI_API_KEY env var.")
        return agents, warnings

    # ── Assistants ────────────────────────────────────────────────────────
    try:
        asst_agents, asst_warns = _discover_assistants(resolved_key, resolved_org)
        agents.extend(asst_agents)
        warnings.extend(asst_warns)
    except Exception as exc:
        warnings.append(f"OpenAI assistant discovery error: {exc}")

    # ── Fine-tuned models ─────────────────────────────────────────────────
    try:
        ft_agents, ft_warns = _discover_fine_tunes(resolved_key, resolved_org)
        agents.extend(ft_agents)
        warnings.extend(ft_warns)
    except Exception as exc:
        warnings.append(f"OpenAI fine-tune discovery error: {exc}")

    return agents, warnings


def _discover_assistants(
    api_key: str,
    organization: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover OpenAI Assistants with their tools and files."""
    import openai

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        kwargs: dict = {"api_key": api_key}
        if organization:
            kwargs["organization"] = organization
        client = openai.OpenAI(**kwargs)

        # Paginate through all assistants (API returns max 100 per page)
        after_cursor = None
        _max_pages = 100  # safety guard: 10,000 assistants max
        for _page in range(_max_pages):
            kwargs_list: dict = {"limit": 100}
            if after_cursor:
                kwargs_list["after"] = after_cursor
            assistants = client.beta.assistants.list(**kwargs_list)
            page_data = getattr(assistants, "data", None) or []
            if not page_data:
                break
            for asst in page_data:
                asst_id = getattr(asst, "id", "unknown")
                asst_name = getattr(asst, "name", None) or asst_id
                model = getattr(asst, "model", "unknown")
                tools = getattr(asst, "tools", []) or []

                # Map assistant tools to MCPTool objects
                mcp_tools: list[MCPTool] = []
                packages: list[Package] = []

                for tool in tools:
                    tool_type = getattr(tool, "type", "")

                    if tool_type == "code_interpreter":
                        mcp_tools.append(
                            MCPTool(
                                name="code_interpreter",
                                description="Executes Python code in a sandbox [HIGH-RISK: code execution]",
                            )
                        )
                    elif tool_type == "file_search":
                        mcp_tools.append(
                            MCPTool(
                                name="file_search",
                                description="Searches through uploaded files using vector store",
                            )
                        )
                    elif tool_type == "function":
                        func = getattr(tool, "function", None)
                        if func:
                            func_name = getattr(func, "name", "unknown")
                            func_desc = getattr(func, "description", "") or ""
                            mcp_tools.append(
                                MCPTool(
                                    name=func_name,
                                    description=func_desc[:200],
                                )
                            )

                # OpenAI SDK itself is a dependency
                packages.append(Package(name="openai", version="unknown", ecosystem="pypi"))

                server = MCPServer(
                    name=f"openai-asst:{asst_name}",
                    transport=TransportType.UNKNOWN,
                    packages=packages,
                    tools=mcp_tools,
                    env={"OPENAI_API_KEY": "***REDACTED***"},
                )

                agent = Agent(
                    name=f"openai-asst:{asst_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"openai://assistants/{asst_id}",
                    source="openai-assistant",
                    version=model,
                    mcp_servers=[server],
                )
                agents.append(agent)

            # Advance pagination cursor — use getattr with strict bool check
            if getattr(assistants, "has_more", False) is True and page_data:
                after_cursor = page_data[-1].id
            else:
                break

    except Exception as exc:
        warnings.append(f"Could not list OpenAI assistants: {exc}")

    return agents, warnings


def _discover_fine_tunes(
    api_key: str,
    organization: str | None,
) -> tuple[list[Agent], list[str]]:
    """Discover fine-tuned models from OpenAI."""
    import openai

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        kwargs: dict = {"api_key": api_key}
        if organization:
            kwargs["organization"] = organization
        client = openai.OpenAI(**kwargs)

        # Paginate through all fine-tuning jobs (API returns max 100 per page)
        ft_after = None
        _ft_max_pages = 100  # safety guard: 10,000 jobs max
        for _ft_page in range(_ft_max_pages):
            ft_kwargs: dict = {"limit": 100}
            if ft_after:
                ft_kwargs["after"] = ft_after
            jobs = client.fine_tuning.jobs.list(**ft_kwargs)
            ft_page_data = getattr(jobs, "data", None) or []
            if not ft_page_data:
                break
            for job in ft_page_data:
                job_id = getattr(job, "id", "unknown")
                model = getattr(job, "model", "unknown")
                fine_tuned_model = getattr(job, "fine_tuned_model", None)
                status = getattr(job, "status", "unknown")
                training_file = getattr(job, "training_file", None) or ""

                # Only inventory completed fine-tunes
                if not fine_tuned_model:
                    continue

                packages = [Package(name="openai", version="unknown", ecosystem="pypi")]

                server = MCPServer(
                    name=f"openai-ft:{fine_tuned_model}",
                    transport=TransportType.UNKNOWN,
                    packages=packages,
                    env={"OPENAI_API_KEY": "***REDACTED***"},
                )

                # Add training file info as a tool descriptor
                if training_file:
                    server.tools.append(
                        MCPTool(
                            name="training_data",
                            description=f"Trained on file {training_file}, base model {model}",
                        )
                    )

                agent = Agent(
                    name=f"openai-ft:{fine_tuned_model}",
                    agent_type=AgentType.CUSTOM,
                    config_path=f"openai://fine-tuning/{job_id}",
                    source="openai-fine-tune",
                    version=f"{status} (base: {model})",
                    mcp_servers=[server],
                )
                agents.append(agent)

            # Advance pagination cursor — strict bool check
            if getattr(jobs, "has_more", False) is True and ft_page_data:
                ft_after = ft_page_data[-1].id
            else:
                break

    except Exception as exc:
        warnings.append(f"Could not list OpenAI fine-tuning jobs: {exc}")

    return agents, warnings
