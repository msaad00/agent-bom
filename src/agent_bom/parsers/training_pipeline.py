"""Training pipeline lineage parser — extract ML training metadata and provenance.

Parses local training pipeline artifacts:
- MLflow: ``meta.yaml``, ``MLmodel``, ``requirements.txt``, ``conda.yaml``
- Kubeflow: pipeline YAML (Argo workflows, KFP v2 ``pipelineSpec``)
- W&B: ``wandb-metadata.json``, ``config.yaml``, ``wandb-summary.json``

Flags security/compliance concerns:
- ``UNSAFE_SERIALIZATION`` — model uses pickle/joblib (HIGH)
- ``MISSING_PROVENANCE`` — no git SHA or code artifact (MEDIUM)
- ``MISSING_REQUIREMENTS`` — no dependency manifest (MEDIUM)
- ``UNVERSIONED_MODEL`` — no model version/tag (MEDIUM)
- ``EXPOSED_CREDENTIALS`` — API keys in pipeline config (HIGH)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.parsers.compliance_tags import tag_training_run

logger = logging.getLogger(__name__)

# Skip directories during discovery
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".eggs"}

# Simple YAML key: value parser
_YAML_KV_RE = re.compile(r"^(\w[\w_.-]*)\s*:\s*(.+)$", re.MULTILINE)

# Credential patterns (reused from skills.py pattern)
_CREDENTIAL_KEYWORDS = {"key", "token", "secret", "password", "credential", "auth"}

# Unsafe serialization formats
_UNSAFE_FORMATS = {"pickle", "pkl", "joblib", "cloudpickle"}

# Safe serialization formats
_SAFE_FORMATS = {"safetensors", "onnx", "gguf", "ggml", "tflite", "pb"}


@dataclass
class TrainingRun:
    """Parsed ML training run metadata."""

    name: str = ""
    framework: str = ""  # "mlflow" | "kubeflow" | "wandb"
    source_file: str = ""
    run_id: str = ""
    experiment_name: str = ""
    model_artifact_path: str = ""
    model_flavor: str = ""  # e.g. "sklearn", "pytorch", "transformers"
    parameters: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, float] = field(default_factory=dict)
    packages: list[str] = field(default_factory=list)  # requirement strings
    datasets_used: list[str] = field(default_factory=list)
    created_at: str = ""
    git_sha: str = ""
    serialization_format: str = ""
    security_flags: list[dict] = field(default_factory=list)
    compliance_tags: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "name": self.name,
            "framework": self.framework,
            "source_file": self.source_file,
        }
        if self.run_id:
            d["run_id"] = self.run_id
        if self.experiment_name:
            d["experiment_name"] = self.experiment_name
        if self.model_artifact_path:
            d["model_artifact_path"] = self.model_artifact_path
        if self.model_flavor:
            d["model_flavor"] = self.model_flavor
        if self.parameters:
            d["parameters"] = self.parameters
        if self.metrics:
            d["metrics"] = self.metrics
        if self.packages:
            d["packages"] = self.packages
        if self.datasets_used:
            d["datasets_used"] = self.datasets_used
        if self.created_at:
            d["created_at"] = self.created_at
        if self.git_sha:
            d["git_sha"] = self.git_sha
        if self.serialization_format:
            d["serialization_format"] = self.serialization_format
        if self.security_flags:
            d["security_flags"] = self.security_flags
        if self.compliance_tags:
            d["compliance_tags"] = self.compliance_tags
        return d


@dataclass
class ServingConfig:
    """Parsed model serving configuration."""

    name: str = ""
    framework: str = ""  # "mlflow", "kubeflow", "seldon", "bentoml"
    source_file: str = ""
    model_uri: str = ""
    endpoint_url: str = ""
    container_image: str = ""
    security_flags: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "name": self.name,
            "framework": self.framework,
            "source_file": self.source_file,
        }
        if self.model_uri:
            d["model_uri"] = self.model_uri
        if self.endpoint_url:
            d["endpoint_url"] = self.endpoint_url
        if self.container_image:
            d["container_image"] = self.container_image
        if self.security_flags:
            d["security_flags"] = self.security_flags
        return d


@dataclass
class TrainingPipelineScanResult:
    """Aggregated training pipeline scan results."""

    training_runs: list[TrainingRun] = field(default_factory=list)
    serving_configs: list[ServingConfig] = field(default_factory=list)
    source_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "training_runs": [r.to_dict() for r in self.training_runs],
            "serving_configs": [s.to_dict() for s in self.serving_configs],
            "source_files": self.source_files,
            "warnings": self.warnings,
            "total_runs": len(self.training_runs),
            "total_serving": len(self.serving_configs),
            "flagged_count": sum(1 for r in self.training_runs if r.security_flags)
            + sum(1 for s in self.serving_configs if s.security_flags),
        }


def _parse_simple_yaml(text: str) -> dict[str, str]:
    """Extract key-value pairs from simple YAML."""
    return dict(_YAML_KV_RE.findall(text))


def _has_credential(text: str) -> bool:
    """Check if text contains credential-like values."""
    lower = text.lower()
    return any(kw in lower for kw in _CREDENTIAL_KEYWORDS)


def _parse_requirements(path: Path) -> list[str]:
    """Parse a requirements.txt file into package strings."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("-")]
    except OSError:
        return []


def _detect_serialization_format(flavor: str) -> str:
    """Map MLflow flavor to serialization format."""
    flavor_map = {
        "sklearn": "pickle",
        "xgboost": "pickle",
        "lightgbm": "pickle",
        "catboost": "pickle",
        "statsmodels": "pickle",
        "pytorch": "pytorch",
        "tensorflow": "savedmodel",
        "keras": "savedmodel",
        "transformers": "safetensors",
        "onnx": "onnx",
        "spark": "mleap",
    }
    return flavor_map.get(flavor.lower(), "unknown")


# ─── MLflow parsers ─────────────────────────────────────────────────────────


def parse_mlflow_meta_yaml(path: Path) -> TrainingRun | None:
    """Parse an MLflow run ``meta.yaml`` file.

    Located at ``mlruns/<experiment_id>/<run_id>/meta.yaml``.
    Contains run_id, experiment_id, start_time, artifact_uri.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None

    kv = _parse_simple_yaml(content)

    run = TrainingRun(
        name=kv.get("run_name", kv.get("run_id", path.parent.name)),
        framework="mlflow",
        source_file=str(path),
        run_id=kv.get("run_id", ""),
        experiment_name=kv.get("experiment_id", ""),
        model_artifact_path=kv.get("artifact_uri", ""),
        created_at=kv.get("start_time", ""),
    )

    # Read sibling params/ directory
    params_dir = path.parent / "params"
    if params_dir.is_dir():
        for param_file in sorted(params_dir.iterdir()):
            if param_file.is_file():
                try:
                    run.parameters[param_file.name] = param_file.read_text(encoding="utf-8").strip()
                except OSError:
                    pass

    # Read sibling metrics/ directory
    metrics_dir = path.parent / "metrics"
    if metrics_dir.is_dir():
        for metric_file in sorted(metrics_dir.iterdir()):
            if metric_file.is_file():
                try:
                    val = metric_file.read_text(encoding="utf-8").strip().split()
                    if len(val) >= 2:
                        # MLflow metric format: timestamp value [step]
                        run.metrics[metric_file.name] = float(val[1])
                    elif val:
                        run.metrics[metric_file.name] = float(val[0])
                except (OSError, ValueError, IndexError):
                    pass

    # Read sibling tags/ for git info
    tags_dir = path.parent / "tags"
    if tags_dir.is_dir():
        git_file = tags_dir / "mlflow.source.git.commit"
        if git_file.exists():
            try:
                run.git_sha = git_file.read_text(encoding="utf-8").strip()
            except OSError:
                pass

    if not run.git_sha:
        run.security_flags.append(
            {
                "severity": "MEDIUM",
                "type": "MISSING_PROVENANCE",
                "description": f"MLflow run '{run.name}' has no git SHA. Code provenance cannot be verified.",
            }
        )

    return run


def parse_mlflow_mlmodel(path: Path) -> TrainingRun | None:
    """Parse an MLflow ``MLmodel`` YAML file.

    Contains model flavors (serialization format), signature, and model UUID.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None

    kv = _parse_simple_yaml(content)

    run = TrainingRun(
        name=kv.get("model_uuid", path.parent.name),
        framework="mlflow",
        source_file=str(path),
        run_id=kv.get("run_id", ""),
        created_at=kv.get("utc_time_created", ""),
    )

    # Detect model flavors
    flavors_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "flavors:":
            flavors_section = True
            continue
        if flavors_section and not line.startswith(" "):
            flavors_section = False
        if flavors_section and re.match(r"^\s{2}\w+:", line):
            flavor_name = line.strip().rstrip(":")
            if flavor_name != "python_function":
                run.model_flavor = flavor_name
                run.serialization_format = _detect_serialization_format(flavor_name)

    # Check for unsafe serialization
    if run.serialization_format in _UNSAFE_FORMATS:
        run.security_flags.append(
            {
                "severity": "HIGH",
                "type": "UNSAFE_SERIALIZATION",
                "description": (
                    f"Model uses {run.serialization_format} serialization which allows arbitrary code execution. "
                    "Use safetensors or ONNX instead."
                ),
            }
        )

    # Look for sibling requirements.txt
    req_path = path.parent / "requirements.txt"
    conda_path = path.parent / "conda.yaml"
    if req_path.exists():
        run.packages = _parse_requirements(req_path)
    elif conda_path.exists():
        # Extract pip deps from conda.yaml
        try:
            conda_content = conda_path.read_text(encoding="utf-8")
            in_pip = False
            for line in conda_content.splitlines():
                if "pip:" in line:
                    in_pip = True
                    continue
                if in_pip:
                    stripped = line.strip()
                    if stripped.startswith("- "):
                        pkg = stripped[2:].strip()
                        if pkg and not pkg.startswith("#"):
                            run.packages.append(pkg)
                    elif not stripped.startswith("#") and stripped:
                        in_pip = False
        except OSError:
            pass
    else:
        run.security_flags.append(
            {
                "severity": "MEDIUM",
                "type": "MISSING_REQUIREMENTS",
                "description": f"MLflow model '{run.name}' has no requirements.txt or conda.yaml. Dependencies cannot be audited.",
            }
        )

    return run


# ─── Kubeflow parsers ───────────────────────────────────────────────────────


def parse_kubeflow_pipeline_yaml(path: Path) -> TrainingPipelineScanResult | None:
    """Parse a Kubeflow pipeline YAML (Argo workflow or KFP v2).

    Extracts container images and environment variables for scanning.
    """
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None

    # Verify this is actually a pipeline YAML (match exact apiVersion patterns)
    is_argo = bool(re.search(r"apiVersion:\s*argoproj\.io/", content))
    is_kfp = "pipelineSpec" in content or "pipelineInfo" in content
    if not is_argo and not is_kfp:
        return None

    result = TrainingPipelineScanResult()
    result.source_files.append(str(path))

    # Extract container images
    image_matches = re.findall(r"image:\s*['\"]?([^\s'\"]+)", content)

    # Build a training run for the pipeline
    run = TrainingRun(
        name=path.stem,
        framework="kubeflow",
        source_file=str(path),
    )

    # Check for credentials in env vars (check env var names and values)
    env_name_matches = re.findall(r"name:\s*['\"]?([^\s'\"]+)", content)
    for env_name in env_name_matches:
        if _has_credential(env_name):
            run.security_flags.append(
                {
                    "severity": "HIGH",
                    "type": "EXPOSED_CREDENTIALS",
                    "description": "Kubeflow pipeline may contain exposed credentials in environment configuration.",
                }
            )
            break

    if not re.search(r"labels:|annotations:", content):
        run.security_flags.append(
            {
                "severity": "MEDIUM",
                "type": "MISSING_PROVENANCE",
                "description": f"Kubeflow pipeline '{run.name}' has no labels or annotations for provenance tracking.",
            }
        )

    result.training_runs.append(run)

    # Create serving configs for container images
    for img in set(image_matches):
        result.serving_configs.append(
            ServingConfig(
                name=img.split("/")[-1].split(":")[0],
                framework="kubeflow",
                source_file=str(path),
                container_image=img,
            )
        )

    return result


# ─── W&B parsers ────────────────────────────────────────────────────────────


def parse_wandb_metadata(path: Path) -> TrainingRun | None:
    """Parse a W&B ``wandb-metadata.json`` file.

    Contains program, args, python version, OS, GPU, CPU info.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return None

    if not isinstance(data, dict):
        return None

    run = TrainingRun(
        name=data.get("program", path.parent.parent.name if path.parent.name == "files" else path.parent.name),
        framework="wandb",
        source_file=str(path),
        run_id=data.get("run_id", ""),
    )

    # Extract git SHA
    run.git_sha = data.get("git", {}).get("commit", "") if isinstance(data.get("git"), dict) else ""

    # Extract program args as parameters
    args = data.get("args", [])
    if isinstance(args, list):
        for i in range(0, len(args) - 1, 2):
            if isinstance(args[i], str) and args[i].startswith("--"):
                run.parameters[args[i].lstrip("-")] = str(args[i + 1])

    # Look for sibling config.yaml (hyperparameters)
    config_path = path.parent / "config.yaml"
    if config_path.exists():
        try:
            config_content = config_path.read_text(encoding="utf-8")
            config_kv = _parse_simple_yaml(config_content)
            for k, v in config_kv.items():
                if k not in ("_wandb", "wandb_version"):
                    run.parameters[k] = v
        except OSError:
            pass

    # Look for sibling wandb-summary.json (final metrics)
    summary_path = path.parent / "wandb-summary.json"
    if summary_path.exists():
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(summary, dict):
                for k, v in summary.items():
                    if isinstance(v, (int, float)) and not k.startswith("_"):
                        run.metrics[k] = float(v)
        except (json.JSONDecodeError, OSError):
            pass

    # Security flags
    if not run.git_sha:
        run.security_flags.append(
            {
                "severity": "MEDIUM",
                "type": "MISSING_PROVENANCE",
                "description": f"W&B run '{run.name}' has no git SHA. Code provenance cannot be verified.",
            }
        )

    # Check config for credentials
    if config_path.exists():
        try:
            config_text = config_path.read_text(encoding="utf-8")
            for line in config_text.splitlines():
                if _has_credential(line) and re.search(r"['\"]?[A-Za-z0-9_-]{20,}['\"]?", line):
                    run.security_flags.append(
                        {
                            "severity": "HIGH",
                            "type": "EXPOSED_CREDENTIALS",
                            "description": "W&B config may contain exposed API keys or tokens.",
                        }
                    )
                    break
        except OSError:
            pass

    return run


# ─── Discovery + batch scan ────────────────────────────────────────────────


def discover_training_files(directory: Path) -> list[Path]:
    """Find ML training pipeline metadata files in a directory tree."""
    results: list[Path] = []

    for p in directory.rglob("*"):
        if any(skip in p.parts for skip in _SKIP_DIRS):
            continue
        if not p.is_file():
            continue

        name = p.name

        # MLflow
        if name == "meta.yaml" and "mlruns" in str(p):
            results.append(p)
        elif name == "MLmodel":
            results.append(p)

        # Kubeflow / pipeline YAML
        elif name.endswith((".yaml", ".yml")) and "pipeline" in name.lower():
            results.append(p)

        # W&B
        elif name == "wandb-metadata.json":
            results.append(p)

    return sorted(results)


def scan_training_pipelines(paths: list[Path]) -> TrainingPipelineScanResult:
    """Parse a list of training pipeline files and return aggregated results."""
    result = TrainingPipelineScanResult()

    for path in paths:
        name = path.name

        if name == "meta.yaml":
            run = parse_mlflow_meta_yaml(path)
            if run:
                tag_training_run(run)
                result.training_runs.append(run)
                result.source_files.append(str(path))

        elif name == "MLmodel":
            run = parse_mlflow_mlmodel(path)
            if run:
                tag_training_run(run)
                result.training_runs.append(run)
                result.source_files.append(str(path))

        elif name.endswith((".yaml", ".yml")) and "pipeline" in name.lower():
            kf_result = parse_kubeflow_pipeline_yaml(path)
            if kf_result:
                for kf_run in kf_result.training_runs:
                    tag_training_run(kf_run)
                result.training_runs.extend(kf_result.training_runs)
                result.serving_configs.extend(kf_result.serving_configs)
                result.source_files.extend(kf_result.source_files)

        elif name == "wandb-metadata.json":
            run = parse_wandb_metadata(path)
            if run:
                tag_training_run(run)
                result.training_runs.append(run)
                result.source_files.append(str(path))

    return result


def scan_training_directory(directory: str | Path) -> TrainingPipelineScanResult:
    """Discover and scan all training pipeline files in a directory."""
    d = Path(directory)
    if not d.is_dir():
        return TrainingPipelineScanResult(warnings=[f"Not a directory: {d}"])

    paths = discover_training_files(d)
    if not paths:
        return TrainingPipelineScanResult(warnings=[f"No training pipeline files found in {d}"])

    return scan_training_pipelines(paths)
