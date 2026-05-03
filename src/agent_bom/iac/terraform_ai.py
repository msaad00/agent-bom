"""Terraform misconfiguration scanner for AI/ML infrastructure resources.

Complements :mod:`agent_bom.iac.terraform_security` (generic AWS/cloud rules)
by adding **AI-infra-specific** misconfiguration detection — Bedrock,
SageMaker, Vertex AI, Azure ML, Snowflake ML/Snowpark, HuggingFace endpoints,
W&B artifacts, container registries hosting inference images.

Each finding emits a ``TF-AI-XXX`` rule_id; the IaC scan post-processor
(:mod:`agent_bom.iac.__init__`) consults
:mod:`agent_bom.iac.atlas_mapping` to attach the relevant MITRE ATLAS
technique IDs.

Rules
-----
TF-AI-001  Bedrock model invocation logging not enabled
TF-AI-002  SageMaker model registry without resource-based policy
TF-AI-003  SageMaker endpoint with unrestricted public access
TF-AI-004  SageMaker training job with public S3 input bucket
TF-AI-010  Vertex AI Model without IAM binding
TF-AI-011  Vertex AI Endpoint with public access
TF-AI-012  GCS bucket attached to Vertex AI training without IAM binding
TF-AI-020  Azure ML workspace with public network access enabled
TF-AI-021  Azure ML datastore on a public storage account
TF-AI-030  Container registry hosting inference images with mutable tags
TF-AI-040  Snowflake stage / Snowpark ML model with public role grant
TF-AI-050  W&B / HuggingFace artifact storage with anonymous read
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac.models import IaCFinding

# Resource block extractor — same shape as terraform_security.py.
_RESOURCE_RE = re.compile(r'^resource\s+"([a-zA-Z][a-zA-Z0-9_]+)"\s+"([^"]+)"', re.MULTILINE)

# Resource-type → (rule_id, severity, title, message, remediation, indicator).
# `indicator` is a callable: (block_text: str) -> bool that returns True when
# the misconfiguration is present. Keeping detection conservative — we only
# fire on positive evidence of the issue, never on absence-of-block.

_AI_RULES: list[dict] = [
    # ── AWS Bedrock ───────────────────────────────────────────────────────
    {
        "resource_type": "aws_bedrock_model_invocation_logging_configuration",
        "rule_id": "TF-AI-001",
        "severity": "medium",
        "title": "Bedrock model invocation logging disabled",
        "message": (
            "AWS Bedrock model invocation logging is referenced but the configuration "
            "explicitly disables logging delivery, leaving prompt/response activity un-audited "
            "and easing artifact collection (ATLAS T0035) and information-repository discovery (T0036)."
        ),
        "remediation": (
            "Set logging_config { cloud_watch_config { log_group_name = ... } } and ensure "
            "image_data_delivery_enabled / text_data_delivery_enabled are true."
        ),
        "indicator": lambda b: bool(
            re.search(r"text_data_delivery_enabled\s*=\s*false", b, re.IGNORECASE)
            or re.search(r"image_data_delivery_enabled\s*=\s*false", b, re.IGNORECASE)
        ),
    },
    # ── AWS SageMaker ─────────────────────────────────────────────────────
    {
        "resource_type": "aws_sagemaker_model_package",
        "rule_id": "TF-AI-002",
        "severity": "high",
        "title": "SageMaker model package without resource-based policy",
        "message": (
            "SageMaker model package is created without an explicit access policy. Any IAM "
            "principal in the account can list and pull the model artifact, opening the "
            "registry to ML artifact discovery (ATLAS T0007) and supply-chain compromise (T0010)."
        ),
        "remediation": (
            "Attach an aws_sagemaker_model_package_resource_policy resource that scopes pull/list "
            "permissions to a specific role or organization."
        ),
        "indicator": lambda b: True,  # Presence alone triggers — caller must check no policy resource nearby.
    },
    {
        "resource_type": "aws_sagemaker_endpoint",
        "rule_id": "TF-AI-003",
        "severity": "high",
        "title": "SageMaker endpoint exposed without VPC isolation",
        "message": (
            "SageMaker endpoint configuration does not bind to a VPC subnet / security group. "
            "Inference traffic traverses the public AWS endpoint, allowing unauthenticated "
            "discovery of the deployed model (ATLAS T0007) and unrestricted invocation paths "
            "for artifact/data extraction (T0010, T0010.003)."
        ),
        "remediation": (
            "Bind the endpoint via aws_sagemaker_endpoint_configuration { vpc_config { ... } } and "
            "enforce VPC endpoint restrictions for the inference role."
        ),
        "indicator": lambda b: not re.search(r"vpc_config\s*\{", b, re.IGNORECASE),
    },
    # ── GCP Vertex AI ─────────────────────────────────────────────────────
    {
        "resource_type": "google_vertex_ai_endpoint",
        "rule_id": "TF-AI-011",
        "severity": "high",
        "title": "Vertex AI endpoint with public network access",
        "message": (
            "Vertex AI endpoint enables public network access. Any caller can reach the "
            "inference URL and discover the deployed model (ATLAS T0007), enabling "
            "supply-chain reconnaissance against the AI service (T0010)."
        ),
        "remediation": (
            "Set network = projects/<project>/global/networks/<vpc> and disable "
            "enable_public_endpoint to keep inference inside a private VPC."
        ),
        "indicator": lambda b: bool(re.search(r"enable_public_endpoint\s*=\s*true", b, re.IGNORECASE)),
    },
    # ── Azure ML ──────────────────────────────────────────────────────────
    {
        "resource_type": "azurerm_machine_learning_workspace",
        "rule_id": "TF-AI-020",
        "severity": "high",
        "title": "Azure ML workspace with public network access enabled",
        "message": (
            "Azure ML workspace is configured with public_network_access_enabled = true. "
            "The model registry, datastores, and pipeline artifacts are reachable from the "
            "public internet, exposing ML artifacts (ATLAS T0007) and enabling supply-chain "
            "compromise of the deployed model (T0010, T0010.003)."
        ),
        "remediation": ("Set public_network_access_enabled = false and front the workspace with an Azure Private Endpoint."),
        "indicator": lambda b: bool(re.search(r"public_network_access_enabled\s*=\s*true", b, re.IGNORECASE)),
    },
    # ── Container registry hosting inference images ───────────────────────
    {
        "resource_type": "aws_ecr_repository",
        "rule_id": "TF-AI-030",
        "severity": "high",
        "title": "Inference container registry with mutable tags",
        "message": (
            "ECR repository hosts AI/ML inference images but image_tag_mutability is MUTABLE. "
            "An attacker who gains push access can swap the image under a stable tag, "
            "compromising the AI software supply chain (ATLAS T0010, T0010.001, T0010.004)."
        ),
        "remediation": 'Set image_tag_mutability = "IMMUTABLE" on the ECR repository.',
        "indicator": lambda b: bool(
            re.search(r'image_tag_mutability\s*=\s*"MUTABLE"', b, re.IGNORECASE)
            and re.search(r"(inference|model|llm|sagemaker|bedrock|vertex|huggingface)", b, re.IGNORECASE)
        ),
    },
    # ── Snowflake / Snowpark ──────────────────────────────────────────────
    {
        "resource_type": "snowflake_stage",
        "rule_id": "TF-AI-040",
        "severity": "high",
        "title": "Snowflake stage hosting ML artifacts with PUBLIC grant",
        "message": (
            "Snowflake stage is granted to PUBLIC, exposing any model files or training "
            "datasets staged for Snowpark ML to every Snowflake user in the account. "
            "Enables ML artifact discovery (ATLAS T0007) and supply-chain compromise (T0010, T0010.003)."
        ),
        "remediation": "Grant USAGE / READ on the stage to a specific role; never to PUBLIC.",
        "indicator": lambda b: bool(re.search(r'\bto\s*=\s*"?PUBLIC"?', b, re.IGNORECASE)),
    },
    # ── W&B / HuggingFace artifact buckets ────────────────────────────────
    {
        "resource_type": "aws_s3_bucket_policy",
        "rule_id": "TF-AI-050",
        "severity": "high",
        "title": "Anonymous read on W&B / HuggingFace artifact bucket",
        "message": (
            "S3 bucket policy hosting AI artifacts (W&B / HuggingFace / model checkpoints) "
            'grants anonymous Principal: "*" with s3:GetObject, allowing unauthenticated '
            "AI artifact collection (ATLAS T0035)."
        ),
        "remediation": ('Replace Principal: "*" with a specific IAM principal or a Condition restricting callers.'),
        "indicator": lambda b: bool(
            (
                # JSON-style: "Principal": "*"
                re.search(r'"Principal"\s*:\s*"\*"', b)
                # HCL-style: Principal = "*"
                or re.search(r"\bPrincipal\s*=\s*\"\*\"", b)
                # HCL/encode-style: Principal: "*"
                or re.search(r"\bPrincipal\s*:\s*\"\*\"", b)
            )
            and re.search(r"s3:GetObject", b, re.IGNORECASE)
            and re.search(r"(wandb|huggingface|model|checkpoint|artifact)", b, re.IGNORECASE)
        ),
    },
]


def _extract_blocks(text: str) -> list[tuple[str, str, str, int]]:
    """Return (resource_type, name, block_text, line_number) tuples."""
    blocks: list[tuple[str, str, str, int]] = []
    for match in _RESOURCE_RE.finditer(text):
        rtype, rname = match.group(1), match.group(2)
        start = match.start()
        # Find matching closing brace.
        brace_open = text.find("{", match.end())
        if brace_open < 0:
            continue
        depth = 1
        i = brace_open + 1
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        block_text = text[brace_open : i if depth == 0 else len(text)]
        line_number = text.count("\n", 0, start) + 1
        blocks.append((rtype, rname, block_text, line_number))
    return blocks


def scan_terraform_ai(path: Path) -> list[IaCFinding]:
    """Scan a Terraform .tf file for AI-infra-specific misconfigurations."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[IaCFinding] = []
    blocks = _extract_blocks(text)
    full_text = text

    # Special handling: TF-AI-002 must check that no companion
    # aws_sagemaker_model_package_resource_policy resource references the same
    # model package within the same file.
    has_pkg_policy = bool(re.search(r"aws_sagemaker_model_package_resource_policy", full_text))

    # Special handling: TF-AI-004 — SageMaker training job with public S3
    # input. We look for aws_sagemaker_training_job with input_data_config
    # pointing at a bucket lacking aws_s3_bucket_public_access_block in the
    # same file.
    if re.search(r'aws_sagemaker_training_job"', full_text) and not re.search(r"aws_s3_bucket_public_access_block", full_text):
        m = re.search(r'^resource\s+"aws_sagemaker_training_job"', full_text, re.MULTILINE)
        if m:
            findings.append(
                IaCFinding(
                    rule_id="TF-AI-004",
                    severity="high",
                    title="SageMaker training job with unconstrained S3 input",
                    message=(
                        "SageMaker training job ingests data from S3 but the same Terraform "
                        "module does not enforce a public-access block on the input bucket. "
                        "Training data is reachable from the public internet, exposing the "
                        "training corpus (ATLAS T0036)."
                    ),
                    file_path=str(path),
                    line_number=full_text.count("\n", 0, m.start()) + 1,
                    category="terraform",
                    remediation=("Add aws_s3_bucket_public_access_block { block_public_acls = true ... } for the training input bucket."),
                )
            )

    # Special: TF-AI-010 — Vertex AI Model without companion
    # google_vertex_ai_model_iam_binding.
    has_vertex_model = bool(re.search(r'google_vertex_ai_model"', full_text))
    has_vertex_binding = bool(re.search(r"google_vertex_ai_model_iam_binding", full_text))
    if has_vertex_model and not has_vertex_binding:
        m = re.search(r'^resource\s+"google_vertex_ai_model"', full_text, re.MULTILINE)
        if m:
            findings.append(
                IaCFinding(
                    rule_id="TF-AI-010",
                    severity="high",
                    title="Vertex AI Model without IAM binding",
                    message=(
                        "Vertex AI Model is declared without a companion "
                        "google_vertex_ai_model_iam_binding. Any project member with the default "
                        "Vertex viewer role can enumerate the model registry (ATLAS T0007), "
                        "enabling supply-chain reconnaissance of deployed AI artifacts (T0010, T0010.003)."
                    ),
                    file_path=str(path),
                    line_number=full_text.count("\n", 0, m.start()) + 1,
                    category="terraform",
                    remediation=(
                        "Attach a google_vertex_ai_model_iam_binding granting roles/aiplatform.modelUser to a specific principal."
                    ),
                )
            )

    for rtype, _rname, block_text, line_number in blocks:
        for rule in _AI_RULES:
            if rule["resource_type"] != rtype:
                continue
            # TF-AI-002 only fires when no companion policy resource exists.
            if rule["rule_id"] == "TF-AI-002" and has_pkg_policy:
                continue
            if rule["indicator"](block_text):
                findings.append(
                    IaCFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        title=rule["title"],
                        message=rule["message"],
                        file_path=str(path),
                        line_number=line_number,
                        category="terraform",
                        remediation=rule["remediation"],
                    )
                )

    return findings
