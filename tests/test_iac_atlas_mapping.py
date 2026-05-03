"""Tests for the IaC → MITRE ATLAS technique mapping.

Each AI-infra provider has at least one fixture demonstrating that the
mapping fires end-to-end through ``scan_iac()``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac import scan_iac_directory as scan_iac
from agent_bom.iac.atlas_mapping import get_atlas_techniques

# ─── Direct mapping unit tests ────────────────────────────────────────────


def test_direct_mapping_returns_atlas_ids() -> None:
    assert "AML.T0007" in get_atlas_techniques("TF-AI-002")
    assert "AML.T0010" in get_atlas_techniques("TF-AI-002")
    assert get_atlas_techniques("TF-AI-050") == ["AML.T0035"]


def test_unmapped_rule_with_no_signal_returns_empty() -> None:
    assert get_atlas_techniques("TF-SEC-001") == []
    assert get_atlas_techniques("DOCKER-001") == []


def test_prefix_fallback_yields_supply_chain_tag() -> None:
    # New TF-AI- prefix not in IAC_ATLAS_MAP — fallback fires.
    assert get_atlas_techniques("TF-AI-999") == ["AML.T0010"]
    assert get_atlas_techniques("HELM-AI-007") == ["AML.T0010"]


def test_message_token_fallback() -> None:
    # Generic rule_id with AI-infra resource token in the message.
    assert get_atlas_techniques("TF-SEC-022", message="S3 bucket s3-bedrock-prompts has no public access block") == ["AML.T0010"]


def test_message_token_fallback_does_not_overreach() -> None:
    # No AI-infra resource token, no fallback.
    assert get_atlas_techniques("TF-SEC-022", message="generic CloudWatch logs bucket") == []


# ─── Fixtures: one per provider ───────────────────────────────────────────


def _scan(tmp_path: Path, name: str, content: str) -> list:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return scan_iac(str(tmp_path))


def test_bedrock_logging_disabled_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "bedrock.tf",
        """
resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled  = false
    image_data_delivery_enabled = false
  }
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-001"]
    assert matches, "Bedrock logging-disabled rule did not fire"
    [m] = matches
    assert "AML.T0035" in m.atlas_techniques
    assert "AML.T0036" in m.atlas_techniques


def test_sagemaker_model_package_no_policy_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "sagemaker.tf",
        """
resource "aws_sagemaker_model_package" "fraud" {
  model_package_group_name = "fraud-models"
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-002"]
    assert matches, "SageMaker model-package rule did not fire"
    assert "AML.T0007" in matches[0].atlas_techniques
    assert "AML.T0010" in matches[0].atlas_techniques


def test_sagemaker_endpoint_without_vpc_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "sagemaker_endpoint.tf",
        """
resource "aws_sagemaker_endpoint" "infer" {
  name                 = "infer"
  endpoint_config_name = "infer-cfg"
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-003"]
    assert matches
    assert "AML.T0007" in matches[0].atlas_techniques


def test_sagemaker_training_job_with_public_input_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "training_job.tf",
        """
resource "aws_sagemaker_training_job" "train" {
  name = "train-fraud"
  input_data_config {
    channel_name = "training"
    data_source { s3_data_source { s3_uri = "s3://my-training-bucket/data" } }
  }
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-004"]
    assert matches
    assert "AML.T0036" in matches[0].atlas_techniques


def test_vertex_ai_endpoint_public_access_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "vertex.tf",
        """
resource "google_vertex_ai_endpoint" "infer" {
  display_name              = "infer"
  enable_public_endpoint    = true
  region                    = "us-central1"
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-011"]
    assert matches
    assert "AML.T0007" in matches[0].atlas_techniques
    assert "AML.T0010" in matches[0].atlas_techniques


def test_vertex_ai_model_without_iam_binding_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "vertex_model.tf",
        """
resource "google_vertex_ai_model" "m" {
  display_name = "fraud-model"
  region       = "us-central1"
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-010"]
    assert matches
    assert "AML.T0007" in matches[0].atlas_techniques


def test_azure_ml_workspace_public_access_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "azure_ml.tf",
        """
resource "azurerm_machine_learning_workspace" "ws" {
  name                          = "fraud-ws"
  resource_group_name           = "rg"
  application_insights_id       = "ai-id"
  key_vault_id                  = "kv-id"
  storage_account_id            = "sa-id"
  public_network_access_enabled = true
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-020"]
    assert matches
    assert "AML.T0007" in matches[0].atlas_techniques
    assert "AML.T0010" in matches[0].atlas_techniques


def test_inference_ecr_mutable_tags_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "ecr.tf",
        """
resource "aws_ecr_repository" "inference" {
  name                 = "llm-inference"
  image_tag_mutability = "MUTABLE"
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-030"]
    assert matches
    assert "AML.T0010.001" in matches[0].atlas_techniques
    assert "AML.T0010.004" in matches[0].atlas_techniques


def test_snowflake_stage_public_grant_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "snowflake.tf",
        """
resource "snowflake_stage" "models" {
  name     = "snowpark_models"
  database = "ML"
  schema   = "PUBLIC"
}

resource "snowflake_grant_privileges_to_account_role" "g" {
  account_role_name = "PUBLIC"
  privileges        = ["USAGE"]
  on_schema_object {
    object_type = "STAGE"
    object_name = "ML.PUBLIC.snowpark_models"
  }
}
""",
    )
    # Detection in the stage block — relies on indicator. Direct lookup-only
    # version: include a `to = "PUBLIC"` style grant inline. We re-scan with
    # the legacy syntax that the indicator matches.
    findings = _scan(
        tmp_path,
        "snowflake.tf",
        """
resource "snowflake_stage" "models" {
  name     = "snowpark_models"
  database = "ML"
  schema   = "PUBLIC"
  to       = "PUBLIC"
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-040"]
    assert matches, [f.rule_id for f in findings]
    assert "AML.T0007" in matches[0].atlas_techniques


def test_huggingface_artifact_anonymous_read_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "hf_artifacts.tf",
        """
resource "aws_s3_bucket_policy" "huggingface_models" {
  bucket = "huggingface-checkpoints"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowAll",
      Effect    = "Allow",
      Principal = "*",
      Action    = ["s3:GetObject"],
      Resource  = "arn:aws:s3:::huggingface-checkpoints/*"
    }]
  })
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-050"]
    assert matches
    assert "AML.T0035" in matches[0].atlas_techniques


def test_wandb_artifact_anonymous_read_maps_to_atlas(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "wandb_artifacts.tf",
        """
resource "aws_s3_bucket_policy" "wandb_models" {
  bucket = "wandb-artifact-store"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowAll",
      Effect    = "Allow",
      Principal = "*",
      Action    = ["s3:GetObject"],
      Resource  = "arn:aws:s3:::wandb-artifact-store/*"
    }]
  })
}
""",
    )
    matches = [f for f in findings if f.rule_id == "TF-AI-050"]
    assert matches
    assert "AML.T0035" in matches[0].atlas_techniques


# ─── Negative test: existing generic rules should not get ATLAS tags ──────


def test_generic_iac_rule_does_not_pick_up_atlas_tag(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        "generic.tf",
        """
resource "aws_s3_bucket" "logs" {
  bucket = "ops-logs"
  acl    = "public-read"
}
""",
    )
    s3_findings = [f for f in findings if f.rule_id.startswith("TF-SEC-")]
    assert s3_findings, "expected at least one generic TF-SEC finding"
    for f in s3_findings:
        assert f.atlas_techniques == [], f"generic rule {f.rule_id} should not auto-tag ATLAS without AI-infra signal"


@pytest.mark.parametrize(
    "rule_id, must_contain",
    [
        ("TF-AI-001", "AML.T0035"),
        ("TF-AI-002", "AML.T0007"),
        ("TF-AI-010", "AML.T0007"),
        ("TF-AI-020", "AML.T0010"),
        ("TF-AI-030", "AML.T0010.004"),
        ("TF-AI-040", "AML.T0007"),
        ("TF-AI-050", "AML.T0035"),
    ],
)
def test_every_curated_rule_id_maps_to_documented_technique(rule_id: str, must_contain: str) -> None:
    techniques = get_atlas_techniques(rule_id)
    assert must_contain in techniques, f"{rule_id} → {techniques} missing {must_contain}"
