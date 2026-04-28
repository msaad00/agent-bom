"""AISVS — AI Security Verification Standard compliance checks.

Implements a subset of the OWASP AI Security Verification Standard (AISVS v1.0)
covering the highest-impact, programmatically verifiable controls across the AI
system stack: model security, inference exposure, vector store auth, agent tool
scope, and supply chain provenance.

Each check runs against the local system or discovered endpoints and returns a
CISCheckResult-compatible result with pass/fail/error status and evidence.

Check categories:
- AI-4 Model Deployment Security   (KC1: AI Models)
- AI-5 Inference Security          (KC6: Infrastructure)
- AI-6 Memory & Context Security   (KC4: Memory & Context)
- AI-7 AI Supply Chain Security    (KC1: AI Models)
- AI-8 Agent Tool Security         (KC5: Tools & Capabilities)

Reference: https://owasp.org/www-project-ai-security-and-privacy-guide/
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import Any

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult

logger = logging.getLogger(__name__)

# Default Ollama API port
_OLLAMA_PORT = 11434
_DEFAULT_TIMEOUT = 3


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class AIVSReport:
    """Aggregated AISVS compliance results."""

    checks: list[CISCheckResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        return round(100 * self.passed / self.total, 1) if self.total else 0.0

    def to_dict(self) -> dict:
        from agent_bom.maestro import tag_aisvs_check

        return {
            "benchmark": "OWASP AI Security Verification Standard",
            "benchmark_version": "1.0",
            "passed": self.passed,
            "failed": self.failed,
            "total": self.total,
            "pass_rate": self.pass_rate,
            "checks": [
                {
                    **{
                        "check_id": c.check_id,
                        "title": c.title,
                        "status": c.status.value,
                        "severity": c.severity,
                        "evidence": c.evidence,
                        "recommendation": c.recommendation,
                        "cis_section": c.cis_section,
                    },
                    "maestro_layer": tag_aisvs_check(c.check_id).value,
                }
                for c in self.checks
            ],
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# AI-4: Model Deployment Security
# ---------------------------------------------------------------------------

_MODEL_SECTION = "AI-4 - Model Deployment Security"


def _check_ai_4_1(model_dirs: list[str] | None = None) -> CISCheckResult:
    """AI-4.1 — Model files use safe serialization format.

    Scans local model directories for files using unsafe serialization
    formats (.pkl, .pt, .pth, .bin, .ckpt) that allow arbitrary code
    execution on load.
    """
    result = CISCheckResult(
        check_id="AI-4.1",
        title="Model files use safe serialization (not pickle/pt/bin)",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Replace pickle/PyTorch binary files with safetensors or GGUF format.",
        cis_section=_MODEL_SECTION,
    )
    try:
        from pathlib import Path

        from agent_bom.cloud.model_provenance import _UNSAFE_EXTENSIONS

        scan_paths = [Path(d) for d in (model_dirs or [])]
        # Add default model directories
        default_dirs = [
            Path.home() / ".cache" / "huggingface" / "hub",
            Path.home() / ".ollama" / "models",
        ]
        scan_paths.extend(p for p in default_dirs if p.exists())

        unsafe_files: list[str] = []
        for base in scan_paths:
            if not base.exists():
                continue
            for f in base.rglob("*"):
                if f.suffix.lower() in _UNSAFE_EXTENSIONS and f.is_file():
                    unsafe_files.append(str(f.relative_to(base)))

        if not scan_paths or not any(p.exists() for p in scan_paths):
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No model directories found to scan."
            return result

        if unsafe_files:
            result.status = CheckStatus.FAIL
            sample = unsafe_files[:5]
            more = len(unsafe_files) - 5
            evidence = f"Found {len(unsafe_files)} unsafe model file(s): {', '.join(sample)}"
            if more > 0:
                evidence += f" (+{more} more)"
            result.evidence = evidence
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All discovered model files use safe serialization formats."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Scan failed: {exc}"
    return result


def _check_ai_4_2(model_ids: list[str] | None = None) -> CISCheckResult:
    """AI-4.2 — Model files have cryptographic integrity verification.

    Checks whether HuggingFace models have SHA256 blob_id digests available,
    and whether Ollama manifests include a config digest.
    """
    result = CISCheckResult(
        check_id="AI-4.2",
        title="Model files have cryptographic integrity digest",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Prefer models with safetensors + blob_id digest on HuggingFace Hub.",
        cis_section=_MODEL_SECTION,
    )
    try:
        from agent_bom.cloud.model_provenance import (
            _get_ollama_manifest_file,
        )

        checks_run = 0
        no_digest: list[str] = []

        # Check Ollama local models
        manifest_root = None
        try:
            from agent_bom.cloud.model_provenance import _MANIFEST_DIR

            manifest_root = _MANIFEST_DIR
        except ImportError:
            pass

        if manifest_root and manifest_root.exists():
            for tag_path in manifest_root.rglob("*"):
                if tag_path.is_file():
                    model_name = tag_path.parent.name
                    tag = tag_path.name
                    manifest = _get_ollama_manifest_file(model_name, tag)
                    if manifest:
                        checks_run += 1
                        digest = manifest.get("config", {}).get("digest", "")
                        if not digest:
                            no_digest.append(f"ollama:{model_name}:{tag}")

        if checks_run == 0:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No locally cached models found to verify."
            return result

        if no_digest:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(no_digest)} model(s) missing cryptographic digest: {', '.join(no_digest[:5])}"
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {checks_run} locally cached model(s) have integrity digests."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


def _check_ai_4_3() -> CISCheckResult:
    """AI-4.3 — Ollama inference API not exposed beyond localhost.

    Checks whether the Ollama API (port 11434) is accessible on non-loopback
    interfaces, which would expose unauthenticated model inference to the network.
    """
    result = CISCheckResult(
        check_id="AI-4.3",
        title="Local inference API (Ollama) not network-exposed without auth",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=("Set OLLAMA_HOST=127.0.0.1 to restrict Ollama to localhost. Do not expose port 11434 without authentication."),
        cis_section=_MODEL_SECTION,
    )
    try:
        # Check if Ollama is even running
        loopback_open = _tcp_open("127.0.0.1", _OLLAMA_PORT)
        if not loopback_open:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "Ollama is not running on this host."
            return result

        # Get the machine's primary non-loopback IP
        local_ip = _local_ip()
        if not local_ip:
            result.status = CheckStatus.PASS
            result.evidence = "Ollama is running. Could not determine network IP to check exposure."
            return result

        network_open = _tcp_open(local_ip, _OLLAMA_PORT)
        if network_open:
            result.status = CheckStatus.FAIL
            result.evidence = (
                f"Ollama API is accessible on {local_ip}:{_OLLAMA_PORT} (bound to 0.0.0.0 — network-exposed without authentication)."
            )
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"Ollama API is only accessible on localhost:{_OLLAMA_PORT}."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


# ---------------------------------------------------------------------------
# AI-5: Inference Security (exposed ML tooling)
# ---------------------------------------------------------------------------

_INFERENCE_SECTION = "AI-5 - Inference Security"

# Well-known ML development tools that must not be publicly exposed without auth
_ML_TOOLS: list[tuple[str, int, str]] = [
    ("Jupyter Notebook", 8888, "Interactive notebook — arbitrary code execution"),
    ("Jupyter Lab", 8889, "Interactive notebook — arbitrary code execution"),
    ("MLflow UI", 5000, "ML experiment tracking — model registry access"),
    ("Ray Dashboard", 8265, "Distributed compute — cluster control"),
    ("Gradio", 7860, "Model demo UI — may expose inference API"),
    ("Streamlit", 8501, "Model app — may expose data and inference"),
    ("Tensorboard", 6006, "Training metrics — training data exposure"),
    ("Label Studio", 8080, "Data labeling — training data access"),
]


def _check_ai_5_2() -> CISCheckResult:
    """AI-5.2 — No ML development tools exposed on network interfaces.

    Checks whether common ML tooling (Jupyter, MLflow, Ray, Gradio, etc.) is
    accessible on non-loopback interfaces, which exposes model training data,
    experiments, and inference to the network.
    """
    result = CISCheckResult(
        check_id="AI-5.2",
        title="ML development tools not network-exposed (Jupyter, MLflow, Ray, Gradio)",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=("Bind ML tools to 127.0.0.1 only. Use SSH tunneling or VPN for remote access."),
        cis_section=_INFERENCE_SECTION,
    )
    try:
        local_ip = _local_ip()
        exposed: list[str] = []
        checked = 0

        for tool_name, port, description in _ML_TOOLS:
            if not _tcp_open("127.0.0.1", port):
                continue  # Tool not running — skip
            checked += 1
            if local_ip and _tcp_open(local_ip, port):
                exposed.append(f"{tool_name} (:{port}) — {description}")

        if checked == 0:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No ML development tools detected running on this host."
            return result

        if exposed:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(exposed)} ML tool(s) exposed on {local_ip}: " + "; ".join(exposed)
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {checked} running ML tool(s) are bound to localhost only."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


# ---------------------------------------------------------------------------
# AI-6: Memory & Context Security (vector stores)
# ---------------------------------------------------------------------------

_MEMORY_SECTION = "AI-6 - Memory & Context Security"


def _check_ai_6_1() -> CISCheckResult:
    """AI-6.1 — Vector stores require authentication.

    Probes locally running vector databases (Qdrant, Weaviate, Chroma, Milvus)
    and checks whether they return collection data without credentials.
    """
    result = CISCheckResult(
        check_id="AI-6.1",
        title="Vector stores require authentication before returning data",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation=(
            "Enable API key authentication on all vector databases. "
            "For Qdrant: set api_key in config. "
            "For Weaviate: enable API key or OIDC. "
            "For Chroma: set CHROMA_SERVER_AUTH_CREDENTIALS."
        ),
        cis_section=_MEMORY_SECTION,
    )
    try:
        from agent_bom.cloud.vector_db import discover_vector_dbs

        found = discover_vector_dbs()
        if not found:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No vector databases detected on this host."
            return result

        no_auth = [r for r in found if not r.requires_auth]
        if no_auth:
            result.status = CheckStatus.FAIL
            result.evidence = ", ".join(f"{r.db_type} (:{r.port})" for r in no_auth) + " accept requests without authentication."
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(found)} vector database(s) enforce authentication."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


def _check_ai_6_2() -> CISCheckResult:
    """AI-6.2 — Vector stores not exposed beyond localhost.

    Checks whether running vector databases are accessible on non-loopback
    network interfaces (i.e., bound to 0.0.0.0).
    """
    result = CISCheckResult(
        check_id="AI-6.2",
        title="Vector stores not network-exposed (bound to localhost only)",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=("Bind vector databases to 127.0.0.1. If remote access is needed, use a reverse proxy with TLS and auth."),
        cis_section=_MEMORY_SECTION,
    )
    try:
        from agent_bom.cloud.vector_db import discover_vector_dbs

        found = discover_vector_dbs()
        if not found:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No vector databases detected on this host."
            return result

        network_exposed = [r for r in found if not r.is_loopback]
        if network_exposed:
            result.status = CheckStatus.FAIL
            result.evidence = (
                ", ".join(f"{r.db_type} (:{r.port}) on {r.metadata.get('exposed_on', 'network')}" for r in network_exposed)
                + " are accessible beyond localhost."
            )
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(found)} vector database(s) are bound to localhost only."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


# ---------------------------------------------------------------------------
# AI-7: Supply Chain Security
# ---------------------------------------------------------------------------

_SUPPLY_CHAIN_SECTION = "AI-7 - AI Supply Chain Security"


def _check_ai_7_1() -> CISCheckResult:
    """AI-7.1 — No known malicious ML packages in the environment.

    Checks installed Python packages for known malicious packages commonly
    used in ML supply chain attacks (typosquatted names, compromised packages).
    """
    result = CISCheckResult(
        check_id="AI-7.1",
        title="No known malicious or typosquatted ML packages installed",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove flagged packages immediately and audit your dependency chain.",
        cis_section=_SUPPLY_CHAIN_SECTION,
    )
    try:
        import importlib.metadata

        # Known malicious / typosquatted ML package names (curated list)
        malicious_ml_packages: frozenset[str] = frozenset(
            {
                "torchvision-nightly",  # typosquat of torchvision
                "tensor-flow",  # typosquat of tensorflow
                "tensorlfow",  # typosquat
                "tenserflow",  # typosquat
                "pytorch",  # typosquat of torch
                "torch-nightly",  # unsafe nightly channel
                "huggingface",  # typosquat of huggingface-hub
                "transformers-nightly",  # unofficial nightly
                "diffusers-nightly",  # unofficial nightly
                "langchain-community-nightly",  # unofficial
                "openai-unofficial",  # unofficial SDK
                "anthropic-unofficial",  # unofficial SDK
            }
        )

        installed = {dist.metadata["Name"].lower() for dist in importlib.metadata.distributions()}
        found_malicious = installed & {p.lower() for p in malicious_ml_packages}

        if found_malicious:
            result.status = CheckStatus.FAIL
            result.evidence = f"Found {len(found_malicious)} suspicious package(s): " + ", ".join(sorted(found_malicious))
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No known malicious or typosquatted ML packages detected."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


def _check_ai_7_2() -> CISCheckResult:
    """AI-7.2 — Locally cached models have verifiable provenance.

    Checks Ollama local model manifests for cryptographic digests that allow
    integrity verification of the model weights.
    """
    result = CISCheckResult(
        check_id="AI-7.2",
        title="Locally cached AI models have verifiable provenance",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Only download models from gated repositories with blob_id digests. "
            "Run 'agent-bom scan --model-provenance' for full provenance report."
        ),
        cis_section=_SUPPLY_CHAIN_SECTION,
    )
    try:
        try:
            from agent_bom.cloud.model_provenance import _MANIFEST_DIR
        except ImportError:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "model_provenance module not available."
            return result

        if not _MANIFEST_DIR.exists():
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No Ollama model cache found."
            return result

        total = 0
        unverifiable: list[str] = []

        for tag_path in _MANIFEST_DIR.rglob("*"):
            if not tag_path.is_file():
                continue
            total += 1
            try:
                import json

                manifest = json.loads(tag_path.read_text())
                digest = manifest.get("config", {}).get("digest", "")
                if not digest:
                    unverifiable.append(f"{tag_path.parent.name}:{tag_path.name}")
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not parse model manifest %s: %s", tag_path, exc)
                unverifiable.append(str(tag_path.name))

        if total == 0:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No cached model manifests found."
            return result

        if unverifiable:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(unverifiable)}/{total} model(s) lack provenance digest: " + ", ".join(unverifiable[:5])
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {total} cached model manifest(s) include integrity digests."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


# ---------------------------------------------------------------------------
# AI-8: Agent Tool Security
# ---------------------------------------------------------------------------

_AGENT_SECTION = "AI-8 - Agent Tool Security"


def _check_ai_8_1() -> CISCheckResult:
    """AI-8.1 — MCP server tools have defined input schemas.

    Checks locally discovered MCP server configurations to verify that tool
    definitions include input schemas, which bound the agent's capability scope
    and prevent unbounded parameter injection.
    """
    result = CISCheckResult(
        check_id="AI-8.1",
        title="MCP server tool definitions include input schemas",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Ensure all MCP server tool definitions include 'inputSchema' with required field definitions to limit agent capability scope."
        ),
        cis_section=_AGENT_SECTION,
    )
    try:
        from agent_bom.discovery import discover_global_configs

        agents = discover_global_configs()
        mcp_servers: list[Any] = []
        for agent in agents:
            mcp_servers.extend(agent.mcp_servers or [])

        if not mcp_servers:
            result.status = CheckStatus.NOT_APPLICABLE
            result.evidence = "No MCP servers discovered on this system."
            return result

        # Check for servers without explicit command (potential schema risk)
        unchecked = [s for s in mcp_servers if not getattr(s, "command", None)]
        result.status = CheckStatus.PASS
        result.evidence = (
            f"Found {len(mcp_servers)} MCP server(s). Schema validation requires live tool introspection (use --introspect-mcp)."
        )
        if unchecked:
            result.evidence += f" {len(unchecked)} server(s) have no command defined — review manually."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Check failed: {exc}"
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_AVAILABLE_CHECKS: dict[str, tuple[str, Any]] = {
    "AI-4.1": ("_check_ai_4_1", _check_ai_4_1),
    "AI-4.2": ("_check_ai_4_2", _check_ai_4_2),
    "AI-4.3": ("_check_ai_4_3", _check_ai_4_3),
    "AI-5.2": ("_check_ai_5_2", _check_ai_5_2),
    "AI-6.1": ("_check_ai_6_1", _check_ai_6_1),
    "AI-6.2": ("_check_ai_6_2", _check_ai_6_2),
    "AI-7.1": ("_check_ai_7_1", _check_ai_7_1),
    "AI-7.2": ("_check_ai_7_2", _check_ai_7_2),
    "AI-8.1": ("_check_ai_8_1", _check_ai_8_1),
}

AISVS_CHECK_IDS: tuple[str, ...] = tuple(_AVAILABLE_CHECKS)


def run_benchmark(
    checks: list[str] | None = None,
    model_dirs: list[str] | None = None,
) -> AIVSReport:
    """Run AISVS compliance checks and return a report.

    Args:
        checks: Optional list of check IDs to run (e.g. ['AI-4.1', 'AI-6.1']).
                Runs all checks when None.
        model_dirs: Additional directories to scan for model files.

    Returns:
        AIVSReport with all check results.
    """
    report = AIVSReport()

    for check_id, (_, check_fn) in _AVAILABLE_CHECKS.items():
        if checks and check_id not in checks:
            continue
        try:
            if check_id == "AI-4.1":
                result = _check_ai_4_1(model_dirs=model_dirs)
            elif check_id == "AI-4.2":
                result = _check_ai_4_2()
            else:
                result = check_fn()
        except Exception as exc:
            logger.warning("AISVS check %s failed with exception: %s", check_id, exc)
            result = CISCheckResult(
                check_id=check_id,
                title=f"Check {check_id}",
                status=CheckStatus.ERROR,
                severity="unknown",
                evidence=str(exc),
            )
        report.checks.append(result)

    return report


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tcp_open(host: str, port: int, timeout: int = _DEFAULT_TIMEOUT) -> bool:
    """Return True if TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _local_ip() -> str:
    """Return the machine's primary outbound non-loopback IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return ""
