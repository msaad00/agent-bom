"""Compliance framework tagging for training pipeline and dataset findings.

Maps security flags from training runs and dataset cards to compliance
framework codes so that every finding carries actionable regulatory context.

Framework mappings:
- OWASP LLM Top 10: LLM03 (Training Data Poisoning)
- MITRE ATLAS: AML.T0020 (Poison Training Data), AML.T0019 (Publish Poisoned Datasets)
- NIST AI RMF: MAP-3.5 (data provenance), GOVERN-1.7 (supply chain governance)
- EU AI Act: ART-10 (Data Governance)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.parsers.dataset_cards import DatasetInfo
    from agent_bom.parsers.training_pipeline import TrainingRun

# ─── Flag → framework code mappings ────────────────────────────────────────

# Training run security flag types → compliance codes
_TRAINING_FLAG_MAP: dict[str, dict[str, list[str]]] = {
    "UNSAFE_SERIALIZATION": {
        "OWASP_LLM": ["LLM03 Training Data Poisoning"],
        "MITRE_ATLAS": ["AML.T0020 Poison Training Data"],
        "NIST_AI_RMF": ["MAP-3.5"],
    },
    "MISSING_PROVENANCE": {
        "OWASP_LLM": ["LLM03 Training Data Poisoning"],
        "MITRE_ATLAS": ["AML.T0020 Poison Training Data"],
        "NIST_AI_RMF": ["MAP-3.5", "GOVERN-1.7"],
    },
    "MISSING_REQUIREMENTS": {
        "NIST_AI_RMF": ["MAP-3.5", "GOVERN-1.7"],
    },
    "EXPOSED_CREDENTIALS": {
        "OWASP_LLM": ["LLM03 Training Data Poisoning"],
        "NIST_AI_RMF": ["GOVERN-1.7"],
    },
    "UNVERSIONED_MODEL": {
        "NIST_AI_RMF": ["MAP-3.5", "GOVERN-1.7"],
    },
}

# Dataset security flag types → compliance codes
_DATASET_FLAG_MAP: dict[str, dict[str, list[str]]] = {
    "UNLICENSED_DATASET": {
        "EU_AI_ACT": ["ART-10 Data Governance"],
        "NIST_AI_RMF": ["MAP-3.5"],
        "OWASP_LLM": ["LLM03 Training Data Poisoning"],
    },
    "NO_DATASET_CARD": {
        "EU_AI_ACT": ["ART-10 Data Governance"],
        "NIST_AI_RMF": ["MAP-3.5"],
    },
    "UNVERSIONED_DATA": {
        "NIST_AI_RMF": ["MAP-3.5"],
        "MITRE_ATLAS": ["AML.T0020 Poison Training Data"],
    },
    "REMOTE_DATA_SOURCE": {
        "MITRE_ATLAS": ["AML.T0019 Publish Poisoned Datasets"],
        "NIST_AI_RMF": ["MAP-3.5"],
    },
}

# Baseline tags applied to ALL training runs (supply chain governance)
_TRAINING_BASELINE: dict[str, list[str]] = {
    "NIST_AI_RMF": ["MAP-3.5", "GOVERN-1.7"],
}

# Baseline tags applied to ALL datasets
_DATASET_BASELINE: dict[str, list[str]] = {
    "NIST_AI_RMF": ["MAP-3.5"],
    "EU_AI_ACT": ["ART-10 Data Governance"],
}


# ─── Tagging functions ─────────────────────────────────────────────────────


def _merge_tags(target: dict[str, list[str]], source: dict[str, list[str]]) -> None:
    """Merge source compliance tags into target, deduplicating values."""
    for framework, codes in source.items():
        if framework not in target:
            target[framework] = []
        for code in codes:
            if code not in target[framework]:
                target[framework].append(code)


def tag_training_run(run: TrainingRun) -> None:
    """Apply compliance framework tags to a training run based on its security flags.

    Modifies ``run.compliance_tags`` in place. Always applies baseline tags
    (MAP-3.5, GOVERN-1.7) plus flag-specific tags.
    """
    tags: dict[str, list[str]] = {}

    # Baseline: every training run gets supply chain governance tags
    _merge_tags(tags, _TRAINING_BASELINE)

    # Flag-specific tags
    for flag in run.security_flags:
        flag_type = flag.get("type", "")
        if flag_type in _TRAINING_FLAG_MAP:
            _merge_tags(tags, _TRAINING_FLAG_MAP[flag_type])

    run.compliance_tags = tags


def tag_dataset(dataset: DatasetInfo) -> None:
    """Apply compliance framework tags to a dataset based on its security flags.

    Modifies ``dataset.compliance_tags`` in place. Always applies baseline tags
    (ART-10, MAP-3.5) plus flag-specific tags.
    """
    tags: dict[str, list[str]] = {}

    # Baseline: every dataset gets data governance tags
    _merge_tags(tags, _DATASET_BASELINE)

    # Flag-specific tags
    for flag in dataset.security_flags:
        flag_type = flag.get("type", "")
        if flag_type in _DATASET_FLAG_MAP:
            _merge_tags(tags, _DATASET_FLAG_MAP[flag_type])

    dataset.compliance_tags = tags
