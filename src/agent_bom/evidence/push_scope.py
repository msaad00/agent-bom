"""Stable, opaque target identities for replacement of pushed scan evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

TARGET_SCOPE_PATTERN = r"^v1:[a-f0-9]{64}$"

_PATH_TARGETS = (
    "config_dir",
    "inventory",
    "sbom_file",
    "image_tars",
    "tf_dirs",
    "gha_path",
    "agent_projects",
    "skill_paths",
    "jupyter_dirs",
    "model_dirs",
    "dataset_dirs",
    "training_dirs",
    "code_paths",
    "ai_inventory_paths",
    "filesystem_paths",
    "iac_paths",
    "external_scan_path",
    "ignore_file",
)
_REMOTE_TARGETS = ("images", "image_platform", "hf_models")
_COLLECTION_OPTIONS = (
    "no_discover",
    "inventory_only",
    "no_scan",
    "dry_run",
    "follow_symlinks",
    "transitive",
    "max_depth",
    "deps_dev",
    "no_skill",
    "skill_only",
    "scan_prompts",
    "browser_extensions",
    "scan_pii",
    "os_packages",
    "dynamic_discovery",
    "dynamic_max_depth",
    "include_processes",
    "include_containers",
    "demo",
    "self_scan",
    "exclude_unfixable",
    "fixable_only",
    "posture",
    "_iac_only",
    "_image_only",
)
_IMPLICIT_EXTERNAL_TARGETS = (
    "aws",
    "azure_flag",
    "gcp_flag",
    "coreweave_flag",
    "databricks_flag",
    "snowflake_flag",
    "nebius_flag",
    "hf_flag",
    "wandb_flag",
    "mlflow_flag",
    "openai_flag",
    "ollama_flag",
    "smithery_flag",
    "mcp_registry_flag",
    "snyk_flag",
    "jira_discover",
    "servicenow_flag",
    "slack_discover",
    "k8s",
    "k8s_mcp",
    "k8s_live",
    "vector_db_scan",
    "gpu_scan_flag",
)


def valid_target_scope(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(TARGET_SCOPE_PATTERN, value) is not None


def cli_target_scope(options: Any) -> str | None:
    """Hash explicit targets before redaction; never infer cloud account scope.

    A collector whose effective account/cluster depends on external credentials
    remains unscoped until a producer supplies an explicit target receipt.
    Output paths, credentials, enrichment and finding gates are not identities.
    """
    if any(getattr(options, field, False) for field in _IMPLICIT_EXTERNAL_TARGETS):
        return None
    targets: dict[str, Any] = {}
    repo = getattr(options, "repo_url", None)
    project = getattr(options, "project", None) or getattr(options, "path", None)
    if repo:
        parsed = urlsplit(repo)
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        targets["repo_url"] = urlunsplit((parsed.scheme.lower(), host.lower(), parsed.path.rstrip("/"), "", ""))
    elif project:
        targets["project"] = str(Path(project).expanduser().resolve())
    for field in _PATH_TARGETS + _REMOTE_TARGETS:
        value = getattr(options, field, None)
        if not value:
            continue
        values = list(value) if isinstance(value, (tuple, list)) else [value]
        targets[field] = sorted({str(Path(item).expanduser().resolve()) if field in _PATH_TARGETS else str(item) for item in values})
    if not targets:
        return None
    targets["collection"] = {field: getattr(options, field, None) for field in _COLLECTION_OPTIONS}
    canonical = json.dumps(targets, sort_keys=True, separators=(",", ":"))
    return "v1:" + hashlib.sha256(canonical.encode()).hexdigest()


def pushed_scope_key(job: Any, result: dict[str, Any]) -> str | None:
    """Legacy pushes retain independent evidence instead of replacing a host."""
    if not result.get("pushed") or getattr(job, "target", None):
        return None
    source = str(getattr(job, "source_id", None) or "").strip()
    scope = result.get("target_scope")
    if source and valid_target_scope(scope):
        return "push:" + json.dumps([source, scope], separators=(",", ":"))
    return "push-unscoped:" + json.dumps([source, str(job.job_id)], separators=(",", ":"))
