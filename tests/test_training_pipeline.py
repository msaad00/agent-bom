"""Tests for training pipeline lineage parser (MLflow, Kubeflow, W&B)."""

import json

from agent_bom.parsers.training_pipeline import (
    TrainingPipelineScanResult,
    discover_training_files,
    parse_kubeflow_pipeline_yaml,
    parse_mlflow_meta_yaml,
    parse_mlflow_mlmodel,
    parse_wandb_metadata,
    scan_training_directory,
)

# ─── MLflow meta.yaml ──────────────────────────────────────────────────────


def test_parse_mlflow_meta_yaml(tmp_path):
    run_dir = tmp_path / "mlruns" / "0" / "abc123"
    run_dir.mkdir(parents=True)

    meta = """artifact_uri: file:///tmp/mlruns/0/abc123/artifacts
run_id: abc123
experiment_id: 0
run_name: my-experiment
start_time: 1709942400000
"""
    (run_dir / "meta.yaml").write_text(meta)

    # Create params
    params_dir = run_dir / "params"
    params_dir.mkdir()
    (params_dir / "learning_rate").write_text("0.001")
    (params_dir / "epochs").write_text("10")

    # Create metrics
    metrics_dir = run_dir / "metrics"
    metrics_dir.mkdir()
    (metrics_dir / "accuracy").write_text("1709942400000 0.95 0")

    # Create git tag
    tags_dir = run_dir / "tags"
    tags_dir.mkdir()
    (tags_dir / "mlflow.source.git.commit").write_text("a1b2c3d4e5f6")

    run = parse_mlflow_meta_yaml(run_dir / "meta.yaml")
    assert run is not None
    assert run.framework == "mlflow"
    assert run.run_id == "abc123"
    assert run.name == "my-experiment"
    assert run.parameters["learning_rate"] == "0.001"
    assert run.parameters["epochs"] == "10"
    assert run.metrics["accuracy"] == 0.95
    assert run.git_sha == "a1b2c3d4e5f6"
    assert run.security_flags == []  # has git SHA


def test_parse_mlflow_meta_yaml_no_git(tmp_path):
    run_dir = tmp_path / "mlruns" / "0" / "def456"
    run_dir.mkdir(parents=True)

    meta = """run_id: def456
experiment_id: 0
"""
    (run_dir / "meta.yaml").write_text(meta)

    run = parse_mlflow_meta_yaml(run_dir / "meta.yaml")
    assert run is not None
    assert len(run.security_flags) == 1
    assert run.security_flags[0]["type"] == "MISSING_PROVENANCE"


def test_parse_mlflow_meta_yaml_missing_file(tmp_path):
    run = parse_mlflow_meta_yaml(tmp_path / "nonexistent.yaml")
    assert run is None


# ─── MLflow MLmodel ─────────────────────────────────────────────────────────


def test_parse_mlflow_mlmodel_sklearn(tmp_path):
    mlmodel = """artifact_path: model
flavors:
  python_function:
    env: conda.yaml
    loader_module: mlflow.sklearn
    model_path: model.pkl
  sklearn:
    pickled_model: model.pkl
    serialization_format: cloudpickle
model_uuid: 12345-abcde
utc_time_created: '2024-03-01 12:00:00'
"""
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "MLmodel").write_text(mlmodel)

    run = parse_mlflow_mlmodel(model_dir / "MLmodel")
    assert run is not None
    assert run.model_flavor == "sklearn"
    assert run.serialization_format == "pickle"
    assert len(run.security_flags) >= 1
    # Should flag unsafe serialization
    unsafe = [f for f in run.security_flags if f["type"] == "UNSAFE_SERIALIZATION"]
    assert len(unsafe) == 1
    assert unsafe[0]["severity"] == "HIGH"


def test_parse_mlflow_mlmodel_with_requirements(tmp_path):
    mlmodel = """flavors:
  transformers:
    model_type: text-generation
"""
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "MLmodel").write_text(mlmodel)
    (model_dir / "requirements.txt").write_text("transformers==4.38.0\ntorch==2.2.0\nsafetensors==0.4.2\n")

    run = parse_mlflow_mlmodel(model_dir / "MLmodel")
    assert run is not None
    assert run.model_flavor == "transformers"
    assert "transformers==4.38.0" in run.packages
    assert "torch==2.2.0" in run.packages
    # No MISSING_REQUIREMENTS flag
    assert not any(f["type"] == "MISSING_REQUIREMENTS" for f in run.security_flags)


def test_parse_mlflow_mlmodel_with_conda(tmp_path):
    mlmodel = """flavors:
  pytorch:
    model_data: data
"""
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "MLmodel").write_text(mlmodel)
    (model_dir / "conda.yaml").write_text("dependencies:\n  - pip:\n    - torch==2.2.0\n    - numpy==1.26.0\n")

    run = parse_mlflow_mlmodel(model_dir / "MLmodel")
    assert run is not None
    assert "torch==2.2.0" in run.packages
    assert "numpy==1.26.0" in run.packages


def test_parse_mlflow_mlmodel_no_requirements(tmp_path):
    mlmodel = """flavors:
  sklearn:
    pickled_model: model.pkl
"""
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "MLmodel").write_text(mlmodel)

    run = parse_mlflow_mlmodel(model_dir / "MLmodel")
    assert run is not None
    missing_req = [f for f in run.security_flags if f["type"] == "MISSING_REQUIREMENTS"]
    assert len(missing_req) == 1


# ─── Kubeflow ───────────────────────────────────────────────────────────────


def test_parse_kubeflow_pipeline_argo(tmp_path):
    pipeline = """apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: training-pipeline
  labels:
    app: ml-training
spec:
  templates:
  - name: train
    container:
      image: us-docker.pkg.dev/ml/training:v1.2
      command: [python, train.py]
  - name: evaluate
    container:
      image: us-docker.pkg.dev/ml/eval:v1.0
"""
    path = tmp_path / "training-pipeline.yaml"
    path.write_text(pipeline)

    result = parse_kubeflow_pipeline_yaml(path)
    assert result is not None
    assert len(result.training_runs) == 1
    assert result.training_runs[0].framework == "kubeflow"
    assert len(result.serving_configs) >= 1
    # Should have container images
    images = [s.container_image for s in result.serving_configs]
    assert any("training:v1.2" in img for img in images)


def test_parse_kubeflow_pipeline_kfp(tmp_path):
    pipeline = """pipelineSpec:
  components:
    comp-train:
      executorLabel: exec-train
  deploymentSpec:
    executors:
      exec-train:
        container:
          image: gcr.io/my-project/trainer:latest
pipelineInfo:
  name: my-kfp-pipeline
"""
    path = tmp_path / "kfp-pipeline.yaml"
    path.write_text(pipeline)

    result = parse_kubeflow_pipeline_yaml(path)
    assert result is not None
    assert len(result.training_runs) == 1


def test_parse_kubeflow_not_pipeline(tmp_path):
    regular_yaml = """apiVersion: v1
kind: ConfigMap
metadata:
  name: just-a-configmap
"""
    path = tmp_path / "pipeline-config.yaml"
    path.write_text(regular_yaml)

    result = parse_kubeflow_pipeline_yaml(path)
    assert result is None


def test_parse_kubeflow_credentials_in_env(tmp_path):
    pipeline = """apiVersion: argoproj.io/v1alpha1
kind: Workflow
spec:
  templates:
  - name: train
    container:
      image: trainer:latest
      env:
      - name: API_KEY
        value: sk-1234567890abcdef1234567890
"""
    path = tmp_path / "pipeline-with-creds.yaml"
    path.write_text(pipeline)

    result = parse_kubeflow_pipeline_yaml(path)
    assert result is not None
    cred_flags = [f for r in result.training_runs for f in r.security_flags if f["type"] == "EXPOSED_CREDENTIALS"]
    assert len(cred_flags) >= 1


# ─── W&B ────────────────────────────────────────────────────────────────────


def test_parse_wandb_metadata(tmp_path):
    metadata = {
        "program": "train.py",
        "run_id": "abc123",
        "args": ["--lr", "0.001", "--epochs", "50"],
        "git": {"commit": "deadbeef12345678"},
        "python": "3.11.0",
    }
    files_dir = tmp_path / "wandb" / "run-20240301" / "files"
    files_dir.mkdir(parents=True)
    (files_dir / "wandb-metadata.json").write_text(json.dumps(metadata))

    run = parse_wandb_metadata(files_dir / "wandb-metadata.json")
    assert run is not None
    assert run.framework == "wandb"
    assert run.run_id == "abc123"
    assert run.git_sha == "deadbeef12345678"
    assert run.parameters.get("lr") == "0.001"
    assert run.parameters.get("epochs") == "50"
    assert run.security_flags == []  # has git SHA


def test_parse_wandb_metadata_no_git(tmp_path):
    metadata = {"program": "train.py", "args": []}
    path = tmp_path / "wandb-metadata.json"
    path.write_text(json.dumps(metadata))

    run = parse_wandb_metadata(path)
    assert run is not None
    assert len(run.security_flags) == 1
    assert run.security_flags[0]["type"] == "MISSING_PROVENANCE"


def test_parse_wandb_with_summary(tmp_path):
    metadata = {"program": "train.py", "git": {"commit": "abc123"}}
    summary = {"loss": 0.123, "accuracy": 0.987, "_runtime": 3600, "_step": 1000}

    path = tmp_path / "wandb-metadata.json"
    path.write_text(json.dumps(metadata))
    (tmp_path / "wandb-summary.json").write_text(json.dumps(summary))

    run = parse_wandb_metadata(path)
    assert run is not None
    assert run.metrics["loss"] == 0.123
    assert run.metrics["accuracy"] == 0.987
    # Underscore-prefixed keys should be skipped
    assert "_runtime" not in run.metrics


def test_parse_wandb_with_config(tmp_path):
    metadata = {"program": "train.py", "git": {"commit": "abc123"}}
    config = """learning_rate: 0.001
batch_size: 32
model_name: bert-base
wandb_version: 0.16.0
"""
    path = tmp_path / "wandb-metadata.json"
    path.write_text(json.dumps(metadata))
    (tmp_path / "config.yaml").write_text(config)

    run = parse_wandb_metadata(path)
    assert run is not None
    assert run.parameters["learning_rate"] == "0.001"
    assert run.parameters["batch_size"] == "32"
    # wandb_version should be skipped
    assert "wandb_version" not in run.parameters


def test_parse_wandb_credential_in_config(tmp_path):
    metadata = {"program": "train.py", "git": {"commit": "abc123"}}
    config = """api_key: sk-1234567890abcdefghijklmnop
model: gpt-4
"""
    path = tmp_path / "wandb-metadata.json"
    path.write_text(json.dumps(metadata))
    (tmp_path / "config.yaml").write_text(config)

    run = parse_wandb_metadata(path)
    assert run is not None
    cred_flags = [f for f in run.security_flags if f["type"] == "EXPOSED_CREDENTIALS"]
    assert len(cred_flags) == 1


def test_parse_wandb_invalid_json(tmp_path):
    path = tmp_path / "wandb-metadata.json"
    path.write_text("not json{{{")

    run = parse_wandb_metadata(path)
    assert run is None


# ─── discover_training_files ────────────────────────────────────────────────


def test_discover_mlflow_files(tmp_path):
    run_dir = tmp_path / "mlruns" / "0" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.yaml").write_text("run_id: run1")

    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "MLmodel").write_text("flavors: {}")

    paths = discover_training_files(tmp_path)
    names = [p.name for p in paths]
    assert "meta.yaml" in names
    assert "MLmodel" in names


def test_discover_wandb_files(tmp_path):
    wandb_dir = tmp_path / "wandb" / "run-123" / "files"
    wandb_dir.mkdir(parents=True)
    (wandb_dir / "wandb-metadata.json").write_text("{}")

    paths = discover_training_files(tmp_path)
    assert any(p.name == "wandb-metadata.json" for p in paths)


def test_discover_pipeline_yaml(tmp_path):
    (tmp_path / "training-pipeline.yaml").write_text("apiVersion: argoproj.io/v1alpha1")

    paths = discover_training_files(tmp_path)
    assert any(p.name == "training-pipeline.yaml" for p in paths)


def test_discover_skips_git_dirs(tmp_path):
    git_dir = tmp_path / ".git" / "mlruns"
    git_dir.mkdir(parents=True)
    (git_dir / "MLmodel").write_text("flavors: {}")

    paths = discover_training_files(tmp_path)
    assert len(paths) == 0


# ─── scan_training_pipelines / scan_training_directory ──────────────────────


def test_scan_training_directory_end_to_end(tmp_path):
    # MLflow run
    run_dir = tmp_path / "mlruns" / "0" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.yaml").write_text("run_id: run1\nrun_name: test-run")

    # W&B run
    wandb_dir = tmp_path / "wandb"
    wandb_dir.mkdir()
    (wandb_dir / "wandb-metadata.json").write_text(json.dumps({"program": "train.py", "git": {"commit": "abc"}}))

    result = scan_training_directory(str(tmp_path))
    assert len(result.training_runs) >= 1
    assert result.source_files


def test_scan_training_directory_nonexistent(tmp_path):
    result = scan_training_directory(str(tmp_path / "nope"))
    assert len(result.warnings) == 1
    assert "Not a directory" in result.warnings[0]


def test_scan_training_directory_empty(tmp_path):
    result = scan_training_directory(str(tmp_path))
    assert len(result.warnings) == 1
    assert "No training pipeline files" in result.warnings[0]


# ─── TrainingPipelineScanResult.to_dict ─────────────────────────────────────


def test_training_scan_result_to_dict():
    result = TrainingPipelineScanResult()
    d = result.to_dict()
    assert d["total_runs"] == 0
    assert d["total_serving"] == 0
    assert d["flagged_count"] == 0


# ─── TrainingRun.to_dict ───────────────────────────────────────────────────


def test_training_run_to_dict(tmp_path):
    run_dir = tmp_path / "mlruns" / "0" / "run1"
    run_dir.mkdir(parents=True)
    meta = "run_id: run1\nrun_name: test\n"
    (run_dir / "meta.yaml").write_text(meta)

    run = parse_mlflow_meta_yaml(run_dir / "meta.yaml")
    d = run.to_dict()
    assert d["name"] == "test"
    assert d["framework"] == "mlflow"
    assert d["run_id"] == "run1"
