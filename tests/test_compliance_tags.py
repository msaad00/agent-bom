"""Tests for compliance framework tagging on training runs and dataset cards."""

import json

from agent_bom.parsers.compliance_tags import tag_dataset, tag_training_run
from agent_bom.parsers.dataset_cards import (
    DatasetInfo,
    scan_datasets,
)
from agent_bom.parsers.training_pipeline import (
    TrainingRun,
    scan_training_pipelines,
)

# ─── TrainingRun tagging ─────────────────────────────────────────────────


def test_training_run_baseline_tags():
    """Every training run gets MAP-3.5 and GOVERN-1.7 baseline tags."""
    run = TrainingRun(name="test", framework="mlflow")
    tag_training_run(run)
    assert "NIST_AI_RMF" in run.compliance_tags
    assert "MAP-3.5" in run.compliance_tags["NIST_AI_RMF"]
    assert "GOVERN-1.7" in run.compliance_tags["NIST_AI_RMF"]


def test_training_run_unsafe_serialization_tags():
    run = TrainingRun(name="test", framework="mlflow")
    run.security_flags.append({"type": "UNSAFE_SERIALIZATION", "severity": "HIGH"})
    tag_training_run(run)
    assert "OWASP_LLM" in run.compliance_tags
    assert "LLM03 Training Data Poisoning" in run.compliance_tags["OWASP_LLM"]
    assert "MITRE_ATLAS" in run.compliance_tags
    assert "AML.T0020 Poison Training Data" in run.compliance_tags["MITRE_ATLAS"]


def test_training_run_missing_provenance_tags():
    run = TrainingRun(name="test", framework="wandb")
    run.security_flags.append({"type": "MISSING_PROVENANCE", "severity": "MEDIUM"})
    tag_training_run(run)
    assert "LLM03 Training Data Poisoning" in run.compliance_tags["OWASP_LLM"]
    assert "AML.T0020 Poison Training Data" in run.compliance_tags["MITRE_ATLAS"]
    assert "MAP-3.5" in run.compliance_tags["NIST_AI_RMF"]
    assert "GOVERN-1.7" in run.compliance_tags["NIST_AI_RMF"]


def test_training_run_exposed_credentials_tags():
    run = TrainingRun(name="test", framework="kubeflow")
    run.security_flags.append({"type": "EXPOSED_CREDENTIALS", "severity": "HIGH"})
    tag_training_run(run)
    assert "LLM03 Training Data Poisoning" in run.compliance_tags["OWASP_LLM"]
    assert "GOVERN-1.7" in run.compliance_tags["NIST_AI_RMF"]


def test_training_run_missing_requirements_tags():
    run = TrainingRun(name="test", framework="mlflow")
    run.security_flags.append({"type": "MISSING_REQUIREMENTS", "severity": "MEDIUM"})
    tag_training_run(run)
    assert "MAP-3.5" in run.compliance_tags["NIST_AI_RMF"]
    assert "GOVERN-1.7" in run.compliance_tags["NIST_AI_RMF"]


def test_training_run_multiple_flags_dedup():
    """Multiple flags with overlapping codes should not produce duplicates."""
    run = TrainingRun(name="test", framework="mlflow")
    run.security_flags.append({"type": "UNSAFE_SERIALIZATION", "severity": "HIGH"})
    run.security_flags.append({"type": "MISSING_PROVENANCE", "severity": "MEDIUM"})
    tag_training_run(run)
    # Both map to LLM03, should appear once
    assert run.compliance_tags["OWASP_LLM"].count("LLM03 Training Data Poisoning") == 1
    # Both map to MAP-3.5 (plus baseline), should appear once
    assert run.compliance_tags["NIST_AI_RMF"].count("MAP-3.5") == 1


def test_training_run_no_flags_still_has_baseline():
    run = TrainingRun(name="clean-run", framework="mlflow")
    tag_training_run(run)
    assert run.compliance_tags["NIST_AI_RMF"] == ["MAP-3.5", "GOVERN-1.7"]
    assert "OWASP_LLM" not in run.compliance_tags


def test_training_run_to_dict_includes_compliance_tags():
    run = TrainingRun(name="test", framework="mlflow")
    tag_training_run(run)
    d = run.to_dict()
    assert "compliance_tags" in d
    assert "NIST_AI_RMF" in d["compliance_tags"]


# ─── DatasetInfo tagging ─────────────────────────────────────────────────


def test_dataset_baseline_tags():
    """Every dataset gets ART-10 and MAP-3.5 baseline tags."""
    ds = DatasetInfo(name="test-ds")
    tag_dataset(ds)
    assert "EU_AI_ACT" in ds.compliance_tags
    assert "ART-10 Data Governance" in ds.compliance_tags["EU_AI_ACT"]
    assert "MAP-3.5" in ds.compliance_tags["NIST_AI_RMF"]


def test_dataset_unlicensed_tags():
    ds = DatasetInfo(name="unlicensed")
    ds.security_flags.append({"type": "UNLICENSED_DATASET", "severity": "MEDIUM"})
    tag_dataset(ds)
    assert "LLM03 Training Data Poisoning" in ds.compliance_tags["OWASP_LLM"]
    assert "ART-10 Data Governance" in ds.compliance_tags["EU_AI_ACT"]


def test_dataset_no_card_tags():
    ds = DatasetInfo(name="no-card")
    ds.security_flags.append({"type": "NO_DATASET_CARD", "severity": "LOW"})
    tag_dataset(ds)
    assert "ART-10 Data Governance" in ds.compliance_tags["EU_AI_ACT"]
    assert "MAP-3.5" in ds.compliance_tags["NIST_AI_RMF"]


def test_dataset_unversioned_data_tags():
    ds = DatasetInfo(name="unversioned")
    ds.security_flags.append({"type": "UNVERSIONED_DATA", "severity": "LOW"})
    tag_dataset(ds)
    assert "AML.T0020 Poison Training Data" in ds.compliance_tags["MITRE_ATLAS"]
    assert "MAP-3.5" in ds.compliance_tags["NIST_AI_RMF"]


def test_dataset_remote_data_source_tags():
    ds = DatasetInfo(name="remote")
    ds.security_flags.append({"type": "REMOTE_DATA_SOURCE", "severity": "INFO"})
    tag_dataset(ds)
    assert "AML.T0019 Publish Poisoned Datasets" in ds.compliance_tags["MITRE_ATLAS"]


def test_dataset_no_flags_still_has_baseline():
    ds = DatasetInfo(name="clean-ds")
    tag_dataset(ds)
    assert ds.compliance_tags["EU_AI_ACT"] == ["ART-10 Data Governance"]
    assert ds.compliance_tags["NIST_AI_RMF"] == ["MAP-3.5"]
    assert "OWASP_LLM" not in ds.compliance_tags


def test_dataset_to_dict_includes_compliance_tags():
    ds = DatasetInfo(name="test")
    tag_dataset(ds)
    d = ds.to_dict()
    assert "compliance_tags" in d


# ─── Integration: tags applied through scan pipelines ────────────────────


def test_scan_training_pipelines_adds_tags(tmp_path):
    """scan_training_pipelines() should auto-tag every run."""
    run_dir = tmp_path / "mlruns" / "0" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "meta.yaml").write_text("run_id: run1\nrun_name: tagged-run\n")

    result = scan_training_pipelines([run_dir / "meta.yaml"])
    assert len(result.training_runs) == 1
    run = result.training_runs[0]
    assert run.compliance_tags  # non-empty
    assert "NIST_AI_RMF" in run.compliance_tags


def test_scan_training_pipelines_mlmodel_tags(tmp_path):
    """MLmodel with unsafe serialization should get OWASP + ATLAS tags."""
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "MLmodel").write_text("flavors:\n  sklearn:\n    pickled_model: model.pkl\n")

    result = scan_training_pipelines([model_dir / "MLmodel"])
    run = result.training_runs[0]
    assert "OWASP_LLM" in run.compliance_tags
    assert "MITRE_ATLAS" in run.compliance_tags


def test_scan_training_pipelines_wandb_tags(tmp_path):
    """W&B run without git SHA should get MISSING_PROVENANCE tags."""
    path = tmp_path / "wandb-metadata.json"
    path.write_text(json.dumps({"program": "train.py", "args": []}))

    result = scan_training_pipelines([path])
    run = result.training_runs[0]
    assert "OWASP_LLM" in run.compliance_tags
    assert "LLM03 Training Data Poisoning" in run.compliance_tags["OWASP_LLM"]


def test_scan_training_pipelines_kubeflow_tags(tmp_path):
    """Kubeflow pipeline with credentials should get EXPOSED_CREDENTIALS tags."""
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
    path = tmp_path / "training-pipeline.yaml"
    path.write_text(pipeline)

    result = scan_training_pipelines([path])
    run = result.training_runs[0]
    assert "OWASP_LLM" in run.compliance_tags


def test_scan_datasets_adds_tags(tmp_path):
    """scan_datasets() should auto-tag every dataset."""
    data = {"dataset_name": "tagged-ds", "license": "apache-2.0"}
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps(data))

    result = scan_datasets([path])
    assert len(result.datasets) == 1
    ds = result.datasets[0]
    assert ds.compliance_tags  # non-empty
    assert "EU_AI_ACT" in ds.compliance_tags


def test_scan_datasets_unlicensed_tags(tmp_path):
    """Unlicensed dataset should get OWASP + EU AI Act tags."""
    data = {"dataset_name": "no-license"}
    path = tmp_path / "dataset_info.json"
    path.write_text(json.dumps(data))

    result = scan_datasets([path])
    ds = result.datasets[0]
    assert "OWASP_LLM" in ds.compliance_tags
    assert "LLM03 Training Data Poisoning" in ds.compliance_tags["OWASP_LLM"]
    assert "ART-10 Data Governance" in ds.compliance_tags["EU_AI_ACT"]


def test_scan_datasets_dvc_unversioned_tags(tmp_path):
    """DVC file without hash should get ATLAS poisoning tags."""
    path = tmp_path / "data.csv.dvc"
    path.write_text("outs:\n  - path: data.csv\n    cache: false\n")

    result = scan_datasets([path])
    ds = result.datasets[0]
    assert "MITRE_ATLAS" in ds.compliance_tags
    assert "AML.T0020 Poison Training Data" in ds.compliance_tags["MITRE_ATLAS"]
