"""MLflow discovery — registered models, experiments, and deployments.

Requires ``mlflow``.  Install with::

    pip install agent-bom mlflow

Authentication uses MLFLOW_TRACKING_URI env var or --mlflow-tracking-uri flag.
"""

from __future__ import annotations

import logging
import os

from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, Package, TransportType

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


def discover(
    tracking_uri: str | None = None,
) -> tuple[list[Agent], list[str]]:
    """Discover AI assets from an MLflow tracking server.

    Discovers registered models (with their versions and dependencies),
    and active experiments.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``mlflow`` is not installed.
    """
    try:
        import mlflow  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("mlflow is required for MLflow discovery. Install with: pip install agent-bom mlflow")

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_uri = tracking_uri or os.environ.get("MLFLOW_TRACKING_URI", "")

    if not resolved_uri:
        warnings.append("MLFLOW_TRACKING_URI not set. Provide --mlflow-tracking-uri or set the MLFLOW_TRACKING_URI env var.")
        return agents, warnings

    # ── Registered Models ─────────────────────────────────────────────────
    try:
        model_agents, model_warns = _discover_registered_models(resolved_uri)
        agents.extend(model_agents)
        warnings.extend(model_warns)
    except Exception as exc:
        warnings.append(f"MLflow model discovery error: {exc}")

    # ── Experiments ───────────────────────────────────────────────────────
    try:
        exp_agents, exp_warns = _discover_experiments(resolved_uri)
        agents.extend(exp_agents)
        warnings.extend(exp_warns)
    except Exception as exc:
        warnings.append(f"MLflow experiment discovery error: {exc}")

    return agents, warnings


def _discover_registered_models(
    tracking_uri: str,
) -> tuple[list[Agent], list[str]]:
    """Discover registered models from MLflow model registry."""
    from mlflow import MlflowClient

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = MlflowClient(tracking_uri=tracking_uri)
        # Paginate through all registered models
        page_token: str | None = None
        all_models = []
        for _page in range(100):  # safety guard: 10,000 models max
            kwargs_m: dict = {"max_results": 100}
            if page_token:
                kwargs_m["page_token"] = page_token
            result_page = client.search_registered_models(**kwargs_m)
            all_models.extend(result_page)
            # MLflow PagedList has .token (str) — must verify it's a real str, not a mock
            raw_token = getattr(result_page, "token", None)
            page_token = raw_token if isinstance(raw_token, str) and raw_token else None
            if not page_token:
                break
        models = all_models

        for model in models:
            model_name = getattr(model, "name", "unknown")
            latest_versions = getattr(model, "latest_versions", []) or []
            description = getattr(model, "description", "") or ""

            # Get packages from the latest version's run
            packages: list[Package] = []
            model_version = "latest"
            model_stage = ""

            for mv in latest_versions:
                version = getattr(mv, "version", "")
                stage = getattr(mv, "current_stage", "")
                run_id = getattr(mv, "run_id", None)
                source = getattr(mv, "source", "")

                if version:
                    model_version = str(version)
                if stage:
                    model_stage = stage

                # Extract pip requirements from model artifacts
                if run_id:
                    try:
                        run_packages = _extract_run_packages(client, run_id)
                        packages.extend(run_packages)
                    except (OSError, ValueError, KeyError) as exc:
                        logger.debug("Failed to extract packages from MLflow run %s: %s", run_id, exc)

                # Extract flavor from source path
                flavor_packages = _extract_flavor_packages(source)
                existing = {p.name for p in packages}
                packages.extend(p for p in flavor_packages if p.name not in existing)

            server = MCPServer(
                name=f"mlflow-model:{model_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
            )

            if description:
                server.tools.append(
                    MCPTool(
                        name="inference",
                        description=description[:200],
                    )
                )

            agent = Agent(
                name=f"mlflow-model:{model_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"mlflow://{tracking_uri}/models/{model_name}",
                source="mlflow-model",
                version=f"v{model_version}" + (f" ({model_stage})" if model_stage else ""),
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list MLflow models: {exc}")

    return agents, warnings


def _discover_experiments(
    tracking_uri: str,
) -> tuple[list[Agent], list[str]]:
    """Discover MLflow experiments with recent runs."""
    from mlflow import MlflowClient

    agents: list[Agent] = []
    warnings: list[str] = []

    try:
        client = MlflowClient(tracking_uri=tracking_uri)
        # Paginate through all experiments
        exp_page_token: str | None = None
        all_experiments = []
        for _exp_pg in range(100):  # safety guard: 10,000 experiments max
            kwargs_e: dict = {"max_results": 100}
            if exp_page_token:
                kwargs_e["page_token"] = exp_page_token
            exp_page = client.search_experiments(**kwargs_e)
            all_experiments.extend(exp_page)
            raw_exp_token = getattr(exp_page, "token", None)
            exp_page_token = raw_exp_token if isinstance(raw_exp_token, str) and raw_exp_token else None
            if not exp_page_token:
                break
        experiments = all_experiments

        for exp in experiments:
            exp_id = getattr(exp, "experiment_id", "0")
            exp_name = getattr(exp, "name", "Default")

            # Skip the default experiment
            if exp_name == "Default" and exp_id == "0":
                continue

            # Get most recent run for package metadata
            packages: list[Package] = []
            try:
                runs = client.search_runs(
                    experiment_ids=[exp_id],
                    max_results=1,
                    order_by=["start_time DESC"],
                )
                if runs:
                    run = runs[0]
                    run_id = getattr(run.info, "run_id", None)
                    if run_id:
                        packages = _extract_run_packages(client, run_id)
            except (OSError, ValueError, KeyError) as exc:
                logger.debug("Failed to extract packages from MLflow experiment %s: %s", exp_id, exc)

            server = MCPServer(
                name=f"mlflow-exp:{exp_name}",
                transport=TransportType.UNKNOWN,
                packages=packages,
            )

            agent = Agent(
                name=f"mlflow-exp:{exp_name}",
                agent_type=AgentType.CUSTOM,
                config_path=f"mlflow://{tracking_uri}/experiments/{exp_id}",
                source="mlflow-experiment",
                version=exp_id,
                mcp_servers=[server],
            )
            agents.append(agent)

    except Exception as exc:
        warnings.append(f"Could not list MLflow experiments: {exc}")

    return agents, warnings


def _extract_run_packages(client, run_id: str) -> list[Package]:
    """Extract pip requirements from an MLflow run's artifacts."""
    packages: list[Package] = []

    try:
        artifacts = client.list_artifacts(run_id)
        # Look for model artifact directories
        for artifact in artifacts:
            path = getattr(artifact, "path", "")
            if path in ("model", "models"):
                # Try to read requirements.txt or conda.yaml
                try:
                    req_path = f"{path}/requirements.txt"
                    req_data = client.download_artifacts(run_id, req_path)
                    if req_data:
                        packages.extend(_parse_requirements_txt(str(req_data)))
                except (OSError, ValueError) as exc:
                    # requirements.txt may not exist for this artifact
                    logger.debug("Could not read requirements.txt for run %s: %s", run_id, exc)

                try:
                    conda_path = f"{path}/conda.yaml"
                    conda_data = client.download_artifacts(run_id, conda_path)
                    if conda_data:
                        packages.extend(_parse_conda_yaml(str(conda_data)))
                except (OSError, ValueError) as exc:
                    # conda.yaml may not exist for this artifact
                    logger.debug("Could not read conda.yaml for run %s: %s", run_id, exc)
    except (OSError, ValueError, KeyError) as exc:
        logger.debug("Could not list artifacts for run %s: %s", run_id, exc)

    return packages


def _extract_flavor_packages(source: str) -> list[Package]:
    """Infer framework packages from MLflow model source/flavor."""
    flavor_map: dict[str, str] = {
        "sklearn": "scikit-learn",
        "pytorch": "torch",
        "tensorflow": "tensorflow",
        "keras": "keras",
        "xgboost": "xgboost",
        "lightgbm": "lightgbm",
        "catboost": "catboost",
        "transformers": "transformers",
        "openai": "openai",
        "langchain": "langchain",
        "pyfunc": "mlflow",
        "spark": "pyspark",
    }

    packages: list[Package] = []
    source_lower = source.lower()

    for flavor, pkg_name in flavor_map.items():
        if flavor in source_lower:
            packages.append(Package(name=pkg_name, version="unknown", ecosystem="pypi"))
            break

    return packages


def _parse_requirements_txt(content: str) -> list[Package]:
    """Parse requirements.txt content into Package objects."""
    packages: list[Package] = []

    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        for sep in ("==", ">=", "<=", "~="):
            if sep in line:
                name, version = line.split(sep, 1)
                name = name.split("[")[0].strip()
                packages.append(Package(name=name, version=version.strip(), ecosystem="pypi"))
                break
        else:
            name = line.split("[")[0].strip()
            if name:
                packages.append(Package(name=name, version="unknown", ecosystem="pypi"))

    return packages


def _parse_conda_yaml(content: str) -> list[Package]:
    """Extract pip packages from conda.yaml content."""
    packages: list[Package] = []

    try:
        import yaml

        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return packages

        deps = data.get("dependencies", [])
        for dep in deps:
            if isinstance(dep, dict) and "pip" in dep:
                for pip_dep in dep["pip"]:
                    for sep in ("==", ">=", "<=", "~="):
                        if sep in pip_dep:
                            name, version = pip_dep.split(sep, 1)
                            name = name.split("[")[0].strip()
                            packages.append(Package(name=name, version=version.strip(), ecosystem="pypi"))
                            break
                    else:
                        name = pip_dep.split("[")[0].strip()
                        if name and not name.startswith("-"):
                            packages.append(Package(name=name, version="unknown", ecosystem="pypi"))
    except (ImportError, ValueError, KeyError) as exc:
        logger.debug("Could not parse conda.yaml: %s", exc)

    return packages
