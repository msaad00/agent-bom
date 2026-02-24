"""Ollama local model discovery — scans for locally downloaded models.

Discovers models from the Ollama API (http://localhost:11434) and/or
the ``~/.ollama/models`` manifest directory.  No extra dependencies required.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package

logger = logging.getLogger(__name__)

_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_MANIFEST_DIR = Path.home() / ".ollama" / "models" / "manifests" / "registry.ollama.ai"


def discover(
    host: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover locally available Ollama models.

    Strategy:
    1. Try the Ollama HTTP API (``/api/tags``) for running server inventory.
    2. Fall back to scanning ``~/.ollama/models/manifests`` on disk.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.
    """
    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_host = host or os.environ.get("OLLAMA_HOST", _DEFAULT_OLLAMA_HOST)

    # ── Strategy 1: Ollama API ───────────────────────────────────────────
    api_models = _discover_via_api(resolved_host)
    if api_models is not None:
        for model in api_models:
            name = model.get("name", "unknown")
            size = model.get("size", 0)
            family = model.get("details", {}).get("family", "")
            param_size = model.get("details", {}).get("parameter_size", "")
            quant = model.get("details", {}).get("quantization_level", "")
            fmt = model.get("details", {}).get("format", "")

            tools = []
            meta_parts = []
            if family:
                meta_parts.append(f"family:{family}")
            if param_size:
                meta_parts.append(f"params:{param_size}")
            if quant:
                meta_parts.append(f"quant:{quant}")
            if fmt:
                meta_parts.append(f"format:{fmt}")
            if size:
                size_gb = size / (1024**3)
                meta_parts.append(f"size:{size_gb:.1f}GB")

            tools.append(MCPTool(
                name=name,
                description=f"Ollama model — {', '.join(meta_parts)}" if meta_parts else "Ollama model",
            ))

            # Model name could be "llama3:8b" or "qwen2.5-coder:7b-instruct-q4_K_M"
            base_name = name.split(":")[0] if ":" in name else name
            tag = name.split(":")[1] if ":" in name else "latest"

            server = MCPServer(
                name=f"ollama/{name}",
                command="ollama",
                args=["run", name],
                tools=tools,
                packages=[Package(
                    name=base_name,
                    version=tag,
                    ecosystem="ollama",
                )],
            )

            agent = Agent(
                name=f"ollama-model-{base_name}",
                agent_type=AgentType.CUSTOM,
                config_path=resolved_host,
                source="ollama-api",
                mcp_servers=[server],
            )
            agents.append(agent)

        return agents, warnings

    # ── Strategy 2: Manifest directory scan ───────────────────────────────
    if _MANIFEST_DIR.is_dir():
        manifests = _discover_from_manifests()
        if manifests:
            for model_name, model_tag, manifest_path in manifests:
                server = MCPServer(
                    name=f"ollama/{model_name}:{model_tag}",
                    command="ollama",
                    args=["run", f"{model_name}:{model_tag}"],
                    packages=[Package(
                        name=model_name,
                        version=model_tag,
                        ecosystem="ollama",
                    )],
                )
                agent = Agent(
                    name=f"ollama-model-{model_name}",
                    agent_type=AgentType.CUSTOM,
                    config_path=str(manifest_path),
                    source="ollama-manifest",
                    mcp_servers=[server],
                )
                agents.append(agent)
        else:
            warnings.append("Ollama manifest directory found but no models detected")
    else:
        warnings.append(
            f"Ollama not detected (no API at {resolved_host}, "
            f"no manifests at {_MANIFEST_DIR})"
        )

    return agents, warnings


def _discover_via_api(host: str) -> list[dict] | None:
    """Try to get model list from Ollama HTTP API. Returns None if unreachable."""
    try:
        import httpx

        resp = httpx.get(f"{host}/api/tags", timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("models", [])
    except Exception:
        pass

    # Fallback: try with urllib (no extra dep)
    try:
        import urllib.request

        url = f"{host}/api/tags"
        if not url.startswith(("http://", "https://")):
            return None
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:  # nosec B310
            if resp.status == 200:
                data = json.loads(resp.read())
                return data.get("models", [])
    except Exception:
        pass

    return None


def _discover_from_manifests() -> list[tuple[str, str, Path]]:
    """Scan ~/.ollama/models/manifests for downloaded model tags.

    Returns list of (model_name, tag, manifest_path).
    """
    results: list[tuple[str, str, Path]] = []

    if not _MANIFEST_DIR.is_dir():
        return results

    # Structure: manifests/registry.ollama.ai/library/<model>/<tag>
    library_dir = _MANIFEST_DIR / "library"
    if not library_dir.is_dir():
        return results

    for model_dir in sorted(library_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        model_name = model_dir.name
        for tag_file in sorted(model_dir.iterdir()):
            if tag_file.is_file():
                tag = tag_file.name
                results.append((model_name, tag, tag_file))

    return results
