"""Typed, mutable option set for one ``scan`` invocation.

Click binds every ``scan`` option by keyword; building this dataclass from
those keywords rejects unknown names exactly as the former explicit signature
did. Stages normalize options in place (presets, profiles, project config), so
later stages read the effective value rather than the raw flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanOptions:
    path: Optional[str]
    project: Optional[str]
    repo_url: Optional[str]
    config_dir: Optional[str]
    inventory: Optional[str]
    no_discover: bool
    inventory_only: bool
    follow_symlinks: bool
    output: Optional[str]
    output_format: str
    dry_run: bool
    offline: bool
    no_scan: bool
    blast_radius_depth: int
    no_tree: bool
    transitive: bool
    max_depth: int
    deps_dev: bool
    license_check: bool
    vex_path: Optional[str]
    generate_vex_flag: bool
    vex_output_path: Optional[str]
    enrich: bool
    compliance: bool
    nvd_api_key: Optional[str]
    scorecard_flag: bool
    quiet: bool
    fail_on_severity: Optional[str]
    exit_zero: bool
    warn_on_severity: Optional[str]
    fail_on_kev: bool
    fail_on_malicious: bool
    fail_if_ai_risk: bool
    save_report: bool
    baseline: Optional[str]
    delta_mode: bool
    policy: Optional[str]
    sbom_file: Optional[str]
    sbom_name: Optional[str]
    images: tuple
    image_tars: tuple
    k8s: bool
    namespace: str
    all_namespaces: bool
    k8s_context: Optional[str]
    registry_user: Optional[str]
    registry_pass: Optional[str]
    image_platform: Optional[str]
    mermaid_mode: str
    push_gateway: Optional[str]
    otel_endpoint: Optional[str]
    tf_dirs: tuple
    gha_path: Optional[str]
    agent_projects: tuple
    skill_paths: tuple
    no_skill: bool
    skill_only: bool
    scan_prompts: bool
    browser_extensions: bool
    jupyter_dirs: tuple
    model_dirs: tuple
    model_provenance: bool
    model_policy_mode: str
    require_model_signatures: bool
    block_unsafe_model_formats: bool
    dataset_dirs: tuple
    scan_pii: bool
    training_dirs: tuple
    hf_models: tuple
    introspect: bool
    introspect_timeout: float
    enforce: bool
    verify_integrity: bool
    verify_instructions: bool
    context_graph_flag: bool
    graph_backend: str
    dynamic_discovery: bool
    dynamic_max_depth: int
    include_processes: bool
    include_containers: bool
    k8s_mcp: bool
    k8s_namespace: str
    k8s_all_namespaces: bool
    k8s_mcp_context: Optional[str]
    health_check: bool
    hc_timeout: float
    ai_enrich: bool
    ai_model: str
    ai_deterministic: Optional[bool]
    ai_gate_findings: bool
    aws: bool
    aws_region: Optional[str]
    aws_profile: Optional[str]
    azure_flag: bool
    azure_subscription: Optional[str]
    gcp_flag: bool
    gcp_project: Optional[str]
    coreweave_flag: bool
    coreweave_context: Optional[str]
    coreweave_namespace: Optional[str]
    databricks_flag: bool
    snowflake_flag: bool
    snowflake_authenticator: str | None
    cortex_observability: bool
    nebius_flag: bool
    nebius_api_key: Optional[str]
    nebius_project_id: Optional[str]
    no_aws_lambda: bool
    aws_include_eks: bool
    aws_include_step_functions: bool
    aws_include_ec2: bool
    aws_include_iam: bool
    aws_deep: bool
    aws_ec2_tag: Optional[str]
    aws_cis_benchmark: bool
    snowflake_cis_benchmark: bool
    azure_cis_benchmark: bool
    gcp_cis_benchmark: bool
    databricks_security: bool
    aisvs_flag: bool
    vector_db_scan: bool
    gpu_scan_flag: bool
    gpu_k8s_context: Optional[str]
    no_dcgm_probe: bool
    hf_flag: bool
    verify_model_hashes: bool
    hf_token: Optional[str]
    hf_username: Optional[str]
    hf_organization: Optional[str]
    wandb_flag: bool
    wandb_api_key: Optional[str]
    wandb_entity: Optional[str]
    wandb_project: Optional[str]
    mlflow_flag: bool
    mlflow_tracking_uri: Optional[str]
    openai_flag: bool
    openai_api_key: Optional[str]
    openai_org_id: Optional[str]
    ollama_flag: bool
    ollama_host: Optional[str]
    smithery_flag: bool
    smithery_token: Optional[str]
    mcp_registry_flag: bool
    auto_update_db: bool
    require_fresh_db: bool
    db_sources: Optional[str]
    snyk_flag: bool
    snyk_token: Optional[str]
    snyk_org: Optional[str]
    remediate_path: Optional[str]
    remediate_sh_path: Optional[str]
    apply_fixes_flag: bool
    apply_dry_run: bool
    code_paths: tuple
    sast_config: str
    ai_inventory_paths: tuple
    filesystem_paths: tuple
    jira_url: Optional[str]
    jira_user: Optional[str]
    jira_token: Optional[str]
    jira_project: Optional[str]
    slack_webhook: Optional[str]
    jira_discover: bool
    servicenow_flag: bool
    servicenow_instance: Optional[str]
    servicenow_token: Optional[str]
    slack_discover: bool
    slack_bot_token: Optional[str]
    push_url: Optional[str]
    push_api_key: Optional[str]
    vanta_token: Optional[str]
    drata_token: Optional[str]
    siem_type: Optional[str]
    siem_url: Optional[str]
    siem_token: Optional[str]
    siem_index: Optional[str]
    siem_format: str
    clickhouse_url: Optional[str]
    verbose: bool
    page: int
    log_level: Optional[str]
    log_json: bool
    log_file: Optional[str]
    no_color: bool
    reproducible: bool
    agent_mode: bool
    agent_token_budget: int
    agent_mode_full: bool
    preset: Optional[str]
    open_report: bool
    offline_html: bool
    compliance_export: Optional[str]
    self_scan: bool
    demo: bool
    correlate_log: Optional[str]
    external_scan_path: Optional[str]
    os_packages: bool
    exclude_unfixable: bool = False
    fixable_only: bool = False
    iac_paths: tuple = ()
    ignore_file: Optional[str] = None
    posture: bool = False
    _iac_only: bool = False
    _image_only: bool = False
    _apply_profile_defaults: bool = True
    k8s_live: bool = False
    k8s_live_namespace: str = "default"
    k8s_live_all_namespaces: bool = False
    k8s_live_context: Optional[str] = None
