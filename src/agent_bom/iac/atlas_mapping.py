"""MITRE ATLAS technique mapping for IaC misconfigurations on AI infrastructure.

Parallel to :mod:`agent_bom.iac.attack_mapping`, but mapped to MITRE ATLAS
(adversarial threat landscape for AI systems) instead of MITRE ATT&CK
Enterprise. Where ATT&CK answers "what enterprise tactic does this enable?",
ATLAS answers the AI-specific question: "what step in the ML kill chain
does this misconfiguration unlock?"

Curation rationale (mirrors :mod:`agent_bom.atlas` policy)
----------------------------------------------------------
- Only IaC rules touching AI/ML infrastructure are mapped — model registries,
  artifact stores, training data buckets, AI agent endpoints. Generic cloud
  hardening rules (encryption-at-rest on a non-AI bucket, IAM wildcards on a
  non-ML role) stay in :mod:`attack_mapping` only.
- Mapped to a deliberately narrow ATLAS technique set:
  * ``AML.T0010`` (AI Supply Chain Compromise) — stale or unsigned model
    artifacts; mutable image tags on inference container registries.
  * ``AML.T0007`` (Discover AI Artifacts) — over-permissive read on a model
    registry / model repository.
  * ``AML.T0036`` (Data from Information Repositories) — over-permissive
    bucket / storage on training data, RAG corpora, or prompt logs.
  * ``AML.T0035`` (AI Artifact Collection) — unrestricted artifact download
    from object storage / model serving endpoints.
- Sub-techniques (T0010.001/.002/.003/.004) are surfaced when the IaC rule
  unambiguously identifies the artifact class.

The mapping is keyed by ``rule_id`` (preferred) with a fall-through to a
``rule_id``-prefix pattern so providers can ship new rules under a stable
prefix without touching this file every time.
"""

from __future__ import annotations

import re

# ─── Direct rule_id → ATLAS techniques ────────────────────────────────────────
#
# Provider-specific AI-infra rules (TF-AI-*, K8S-AI-*, HELM-AI-*, CFN-AI-*,
# DOCKER-AI-*) are mapped here. The IaC scanner emits these rule IDs when an
# AI/ML resource (Bedrock, SageMaker, Vertex, Azure ML, W&B, HuggingFace,
# Snowflake ML) has a misconfiguration that exposes one of the four ATLAS
# techniques above.

IAC_ATLAS_MAP: dict[str, list[str]] = {
    # ── AWS Bedrock / SageMaker ───────────────────────────────────────────
    # Bedrock model invocation logging not enabled — eases T0035 (artifact
    # collection) and T0036 (data from information repositories).
    "TF-AI-001": ["AML.T0035", "AML.T0036"],
    # SageMaker model registry without resource-based access policy —
    # over-permissive read on a model registry.
    "TF-AI-002": ["AML.T0007", "AML.T0010", "AML.T0010.003"],
    # SageMaker endpoint with unrestricted public access — supply chain
    # compromise via deployed model + artifact discovery.
    "TF-AI-003": ["AML.T0007", "AML.T0010", "AML.T0010.003"],
    # SageMaker training job with public S3 input — training-data information
    # repository exposure.
    "TF-AI-004": ["AML.T0036"],
    # ── GCP Vertex AI ─────────────────────────────────────────────────────
    # Vertex AI Model with no IAM binding — over-permissive read on the
    # model registry.
    "TF-AI-010": ["AML.T0007", "AML.T0010", "AML.T0010.003"],
    # Vertex AI Endpoint with public access — discoverable inference API.
    "TF-AI-011": ["AML.T0007", "AML.T0010", "AML.T0010.003"],
    # GCS bucket attached to Vertex AI training without IAM binding — open
    # training-data corpus.
    "TF-AI-012": ["AML.T0035", "AML.T0036"],
    # ── Azure ML ──────────────────────────────────────────────────────────
    # Azure ML workspace with public network access enabled — model registry
    # discovery + artifact collection.
    "TF-AI-020": ["AML.T0007", "AML.T0010", "AML.T0010.003"],
    # Azure ML datastore on a public storage account — training-data
    # repository exposure.
    "TF-AI-021": ["AML.T0036"],
    # ── HuggingFace / Snowflake / W&B / generic AI registry ───────────────
    # Container registry storing inference images with mutable tags or no
    # signature verification — supply chain compromise on the runtime.
    "TF-AI-030": ["AML.T0010", "AML.T0010.001", "AML.T0010.004"],
    # Snowflake stage / Snowpark ML model storage with public role grant —
    # over-permissive read on a model registry.
    "TF-AI-040": ["AML.T0007", "AML.T0010", "AML.T0010.003"],
    # W&B / HuggingFace artifact storage with anonymous read — artifact
    # collection.
    "TF-AI-050": ["AML.T0035"],
    # ── Kubernetes-hosted inference / vector / RAG infra ──────────────────
    # K8s AI-inference Deployment exposed via Service without auth —
    # discoverable inference endpoint.
    "K8S-AI-001": ["AML.T0007", "AML.T0010"],
    # K8s PV / PVC mounting an open training dataset volume.
    "K8S-AI-002": ["AML.T0035", "AML.T0036"],
    # ── Snowflake DCM — AI-data relevant rules ─────────────────────────────
    # DCM-001: MANAGE GRANTS — lets recipient read/delegate on any Snowflake
    # object including Cortex models, Snowpark stages, and ML feature stores.
    "DCM-001": ["AML.T0007", "AML.T0036"],
    # DCM-005: SPCS SERVICE without network policy — SPCS hosts AI inference
    # containers; an unrestricted service is a discoverable inference endpoint.
    "DCM-005": ["AML.T0010", "AML.T0010.003"],
    # DCM-006: GRANT ACCOUNTADMIN/SECURITYADMIN — account-level admin provides
    # full read access to every Snowflake ML registry and artifact store.
    "DCM-006": ["AML.T0007", "AML.T0010"],
    # DCM-008: Privilege to PUBLIC — exposes Snowflake tables/stages/models to
    # every account user, enabling AI artifact discovery and collection.
    "DCM-008": ["AML.T0007", "AML.T0035"],
}

# ─── Resource-type prefix fallback ─────────────────────────────────────────
#
# If a rule_id is not in the table above, but its prefix indicates AI-infra
# scope, fall through to a coarse default. This lets new provider plugins
# ship without an IAC_ATLAS_MAP edit.

_AI_PREFIX_DEFAULTS: dict[str, list[str]] = {
    "TF-AI-": ["AML.T0010"],
    "K8S-AI-": ["AML.T0010"],
    "HELM-AI-": ["AML.T0010"],
    "CFN-AI-": ["AML.T0010"],
    "DOCKER-AI-": ["AML.T0010", "AML.T0010.004"],
}

# ─── Heuristic resource-token fallback ─────────────────────────────────────
#
# Last-resort: if a finding mentions an AI-infra resource type in its rule
# message OR resource path, surface the most conservative tag (T0010). This
# is intentionally narrow — only triggered when no direct mapping exists.

_AI_RESOURCE_TOKENS: tuple[str, ...] = (
    "bedrock",
    "sagemaker",
    "vertex",
    "azureml",
    "azure_ml",
    "azurerm_machine_learning",
    "huggingface",
    "wandb",
    "snowflake_ml",
    "snowpark",
    "snowflake_stage",
    "google_vertex_ai",
)
_AI_TOKEN_RE = re.compile(r"|".join(re.escape(t) for t in _AI_RESOURCE_TOKENS), re.IGNORECASE)


def get_atlas_techniques(rule_id: str, *, message: str | None = None) -> list[str]:
    """Return MITRE ATLAS technique IDs for a given IaC rule.

    Resolution order:
    1. Direct lookup in :data:`IAC_ATLAS_MAP`.
    2. Prefix match in :data:`_AI_PREFIX_DEFAULTS` (e.g. ``TF-AI-``).
    3. If ``message`` mentions an AI-infra resource token, return
       ``["AML.T0010"]`` as a conservative supply-chain tag.
    4. Otherwise return an empty list.
    """
    direct = IAC_ATLAS_MAP.get(rule_id)
    if direct:
        return list(direct)

    for prefix, tags in _AI_PREFIX_DEFAULTS.items():
        if rule_id.startswith(prefix):
            return list(tags)

    if message and _AI_TOKEN_RE.search(message):
        return ["AML.T0010"]

    return []
