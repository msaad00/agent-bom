"""Call sites moved onto agent_bom.core.settings parse valid values exactly as before.

Each table pins how a site treated unset, "", "0", "false", "no" and padded
values before the migration; the same tables must hold afterwards.
"""

from __future__ import annotations

import os

import click
import pytest

UNSET = object()


def _set(monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
    if value is UNSET:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, str(value))


FLAG_TABLE = [
    (UNSET, False),
    ("", False),
    ("0", False),
    ("false", False),
    ("no", False),
    ("off", False),
    ("1", True),
    ("true", True),
    (" YES ", True),
    ("on", True),
]


# ── push.py ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, ""), ("", ""), ("  team-a  ", "team-a"), ("0", "0"), ("no", "no")])
def test_push_identity_strings(monkeypatch, raw, expected):
    from agent_bom import push

    for name in ("AGENT_BOM_PUSH_ENROLLMENT_NAME", "AGENT_BOM_PUSH_OWNER", "AGENT_BOM_PUSH_ENVIRONMENT", "AGENT_BOM_PUSH_MDM_PROVIDER"):
        _set(monkeypatch, name, raw)
    _set(monkeypatch, "AGENT_BOM_PUSH_SOURCE_ID", "src-1")
    identity = push._endpoint_identity_from_env()
    assert identity["enrollment_name"] == identity["owner"] == identity["environment"] == identity["mdm_provider"] == expected
    assert identity["source_id"] == "src-1"


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, []), ("", []), (" a, ,b ,", ["a", "b"]), ("0", ["0"])])
def test_push_tags_csv(monkeypatch, raw, expected):
    from agent_bom import push

    _set(monkeypatch, "AGENT_BOM_PUSH_TAGS", raw)
    assert push._endpoint_identity_from_env()["tags"] == expected


def test_push_source_id_and_tls(monkeypatch):
    from agent_bom import push

    _set(monkeypatch, "AGENT_BOM_PUSH_SOURCE_ID", "  ")
    assert len(push.generate_source_id()) == 12
    _set(monkeypatch, "AGENT_BOM_PUSH_SOURCE_ID", " fixed ")
    assert push.generate_source_id() == "fixed"
    _set(monkeypatch, "AGENT_BOM_PUSH_TLS_CERT_FILE", " c.pem ")
    _set(monkeypatch, "AGENT_BOM_PUSH_TLS_KEY_FILE", UNSET)
    assert push._push_tls_cert() is None
    _set(monkeypatch, "AGENT_BOM_PUSH_TLS_KEY_FILE", "k.pem")
    assert push._push_tls_cert() == ("c.pem", "k.pem")
    _set(monkeypatch, "AGENT_BOM_PUSH_TLS_CA_FILE", "")
    assert push._push_tls_verify() is True
    _set(monkeypatch, "AGENT_BOM_PUSH_TLS_CA_FILE", " ca.pem")
    assert push._push_tls_verify() == "ca.pem"


# ── siem ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("raw", "expected"), FLAG_TABLE)
def test_siem_private_egress_flag(monkeypatch, raw, expected):
    from agent_bom import siem

    captured = {}
    monkeypatch.setattr(siem, "create_connector", lambda name, config: captured.setdefault("config", config))
    _set(monkeypatch, "AGENT_BOM_SIEM_TYPE", "splunk")
    _set(monkeypatch, "AGENT_BOM_SIEM_URL", "https://siem.example.test")
    _set(monkeypatch, "AGENT_BOM_SIEM_TOKEN", "t")
    _set(monkeypatch, "AGENT_BOM_SIEM_INDEX", UNSET)
    _set(monkeypatch, "AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", raw)
    siem.create_from_env()
    config = captured["config"]
    assert config.allow_private_networks is expected
    assert (config.name, config.url, config.token, config.index) == ("splunk", "https://siem.example.test", "t", "")


@pytest.mark.parametrize("raw", [UNSET, ""])
def test_siem_disabled_without_type(monkeypatch, raw):
    from agent_bom import siem

    _set(monkeypatch, "AGENT_BOM_SIEM_TYPE", raw)
    assert siem.create_from_env() is None


def test_otlp_logs_health_reads_endpoint_and_headers(monkeypatch):
    from agent_bom.siem import otlp_logs

    _set(monkeypatch, otlp_logs.ENDPOINT_ENV, "  ")
    _set(monkeypatch, otlp_logs.HEADERS_ENV, UNSET)
    assert otlp_logs.audit_otlp_health()["otlp_logs_export"] == "disabled"
    assert otlp_logs.configure_audit_otlp_from_env() is None
    _set(monkeypatch, otlp_logs.ENDPOINT_ENV, "https://otel.example.test")
    _set(monkeypatch, otlp_logs.HEADERS_ENV, " a=b ")
    health = otlp_logs.audit_otlp_health()
    assert health["otlp_logs_endpoint_configured"] is True
    assert health["otlp_logs_headers_configured"] is True


# ── proxy_sandbox.py ─────────────────────────────────────────────


SANDBOX_ENV = (
    "AGENT_BOM_MCP_SANDBOX",
    "AGENT_BOM_MCP_SANDBOX_RUNTIME",
    "AGENT_BOM_MCP_SANDBOX_EGRESS",
    "AGENT_BOM_MCP_SANDBOX_IMAGE",
    "AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY",
    "AGENT_BOM_MCP_SANDBOX_MOUNTS",
    "AGENT_BOM_MCP_SANDBOX_USER",
    "AGENT_BOM_MCP_SANDBOX_CPUS",
    "AGENT_BOM_MCP_SANDBOX_MEMORY",
    "AGENT_BOM_MCP_SANDBOX_TMPFS_SIZE",
    "AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT",
    "AGENT_BOM_MCP_SANDBOX_TIMEOUT_SECONDS",
    "AGENT_BOM_MCP_SANDBOX_SERVER_MODE",
    "AGENT_BOM_SERVER_MODE",
)


@pytest.fixture
def clean_sandbox_env(monkeypatch):
    for name in SANDBOX_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(UNSET, True), ("", False), ("0", False), ("false", False), ("no", False), ("1", True), ("on", True), ("anything", True)],
)
def test_sandbox_enabled_env(monkeypatch, clean_sandbox_env, raw, expected):
    from agent_bom.proxy_sandbox import sandbox_config_from_env

    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX", raw)
    assert sandbox_config_from_env().enabled is expected


def test_sandbox_defaults_and_overrides(monkeypatch, clean_sandbox_env):
    from agent_bom.proxy_sandbox import SandboxConfig, sandbox_config_from_env

    default = sandbox_config_from_env()
    baseline = SandboxConfig()
    assert (default.runtime, default.egress_policy, default.image, default.image_pin_policy) == ("auto", "deny", None, "warn")
    assert (default.cpus, default.memory, default.tmpfs_size, default.user) == (baseline.cpus, baseline.memory, baseline.tmpfs_size, None)
    assert (default.pids_limit, default.timeout_seconds) == (baseline.pids_limit, baseline.timeout_seconds)
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_RUNTIME", " Docker ")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_EGRESS", "Allow-All")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY", "ENFORCE")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_IMAGE", "img@sha256:" + "a" * 64)
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_USER", "1000:1000")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_CPUS", "2")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_MEMORY", "1g")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_TMPFS_SIZE", "16m")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT", "64")
    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_TIMEOUT_SECONDS", "")
    config = sandbox_config_from_env()
    assert (config.runtime, config.egress_policy, config.image_pin_policy) == ("docker", "allow_all", "enforce")
    assert (config.user, config.cpus, config.memory, config.tmpfs_size, config.pids_limit) == ("1000:1000", "2", "1g", "16m", 64)
    assert config.timeout_seconds == baseline.timeout_seconds
    assert sandbox_config_from_env(runtime="podman", cpus="4").runtime == "podman"


@pytest.mark.parametrize("raw", ["0", "-1", "ten"])
def test_sandbox_positive_int_rejects(monkeypatch, clean_sandbox_env, raw):
    from agent_bom.proxy_sandbox import sandbox_config_from_env

    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT", raw)
    with pytest.raises(ValueError, match="AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT must be a positive integer"):
        sandbox_config_from_env()


@pytest.mark.parametrize(
    "name", ["AGENT_BOM_MCP_SANDBOX_RUNTIME", "AGENT_BOM_MCP_SANDBOX_EGRESS", "AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY"]
)
def test_sandbox_rejects_unknown_choices(monkeypatch, clean_sandbox_env, name):
    from agent_bom.proxy_sandbox import sandbox_config_from_env

    _set(monkeypatch, name, "bogus")
    with pytest.raises(ValueError):
        sandbox_config_from_env()


@pytest.mark.parametrize(
    ("explicit", "generic", "expected"),
    [(UNSET, UNSET, False), (UNSET, "1", True), ("", "1", False), ("0", "1", False), ("yes", UNSET, True), (UNSET, "no", False)],
)
def test_sandbox_server_mode_first_set_wins(monkeypatch, clean_sandbox_env, explicit, generic, expected):
    from agent_bom.proxy_sandbox import describe_proxy_sandbox_posture

    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_SERVER_MODE", explicit)
    _set(monkeypatch, "AGENT_BOM_SERVER_MODE", generic)
    posture = describe_proxy_sandbox_posture()
    assert posture["server_mode"] is expected
    assert posture["image_pin_policy_effective_default"] == ("enforce" if expected else "warn")


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, "warn"), ("", "warn"), (" OFF ", "off"), ("bogus", "warn")])
def test_sandbox_posture_default_policy(monkeypatch, clean_sandbox_env, raw, expected):
    from agent_bom.proxy_sandbox import describe_proxy_sandbox_posture

    _set(monkeypatch, "AGENT_BOM_MCP_SANDBOX_IMAGE_PIN_POLICY", raw)
    assert describe_proxy_sandbox_posture()["image_pin_policy_default"] == expected


# ── cli/_server.py ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(("raw", "expected"), FLAG_TABLE)
def test_cli_server_env_truthy(monkeypatch, raw, expected):
    from agent_bom.cli import _server

    _set(monkeypatch, "AGENT_BOM_TEST_FLAG", raw)
    assert _server._env_truthy("AGENT_BOM_TEST_FLAG") is expected


def test_cli_server_tls_kwargs(monkeypatch):
    from agent_bom.cli import _server

    for name in ("AGENT_BOM_TLS_CERT_FILE", "AGENT_BOM_TLS_KEY_FILE", "AGENT_BOM_TLS_CLIENT_CA_FILE", "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT"):
        _set(monkeypatch, name, UNSET)
    assert _server._uvicorn_tls_kwargs() == {}
    _set(monkeypatch, "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT", " yes ")
    with pytest.raises(click.ClickException, match="requires AGENT_BOM_TLS_CLIENT_CA_FILE"):
        _server._uvicorn_tls_kwargs()
    _set(monkeypatch, "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT", "no")
    _set(monkeypatch, "AGENT_BOM_TLS_CERT_FILE", " cert.pem ")
    with pytest.raises(click.ClickException, match="must be configured together"):
        _server._uvicorn_tls_kwargs()


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, "In-memory (ephemeral)"),
        ({"SNOWFLAKE_ACCOUNT": "acct", "AGENT_BOM_POSTGRES_URL": "postgresql://x"}, "Snowflake"),
        ({"AGENT_BOM_GRAPH_BACKEND": " Neptune ", "AGENT_BOM_POSTGRES_URL": "postgresql://x"}, "In-memory (ephemeral)"),
        ({"AGENT_BOM_POSTGRES_URL": "postgresql://x", "AGENT_BOM_DB": "a.db"}, "PostgreSQL"),
        ({"AGENT_BOM_DB": "a.db"}, "SQLite"),
        ({"SNOWFLAKE_ACCOUNT": "", "AGENT_BOM_DB": "a.db"}, "SQLite"),
    ],
)
def test_cli_server_storage_summary_mirrors_lifespan_selection(monkeypatch, env, expected):
    from agent_bom.api import stores
    from agent_bom.cli import _server

    monkeypatch.setattr(stores, "_store", None)
    for name in ("SNOWFLAKE_ACCOUNT", "AGENT_BOM_GRAPH_BACKEND", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert _server._storage_summary(persist=None) == expected


def test_cli_server_analytics_backend_resolution(monkeypatch):
    from agent_bom.cli import _server

    kwargs = {"analytics_buffered": False, "analytics_flush_interval": 1.0, "analytics_max_batch": 1, "analytics_max_queue": 1}
    for suffix in (
        "ANALYTICS_BACKEND",
        "CLICKHOUSE_URL",
        "CLICKHOUSE_BUFFERED",
        "CLICKHOUSE_FLUSH_INTERVAL",
        "CLICKHOUSE_MAX_BATCH",
        "CLICKHOUSE_MAX_QUEUE",
    ):
        monkeypatch.delenv(f"AGENT_BOM_{suffix}", raising=False)
    assert _server._configure_analytics_backend(analytics_backend="auto", clickhouse_url=None, **kwargs) == ("disabled", None)
    _set(monkeypatch, "AGENT_BOM_CLICKHOUSE_URL", " http://ch:8123 ")
    assert _server._configure_analytics_backend(analytics_backend="", clickhouse_url=None, **kwargs) == ("clickhouse", "http://ch:8123")


# ── cli tenant / findings / profiles / scan helpers ─────────────────────────


@pytest.mark.parametrize(("raw", "expected"), FLAG_TABLE)
def test_cli_tenant_boundary_flag(monkeypatch, raw, expected):
    from agent_bom.cli import _tenant

    _set(monkeypatch, "AGENT_BOM_REQUIRE_TENANT_BOUNDARY", raw)
    _set(monkeypatch, "AGENT_BOM_CONTROL_PLANE_REPLICAS", UNSET)
    assert _tenant._multi_tenant_signals_present() is expected


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, False), ("", False), ("1", False), (" 2 ", True), ("x", False), ("-3", False)])
def test_cli_tenant_replicas_signal(monkeypatch, raw, expected):
    from agent_bom.cli import _tenant

    _set(monkeypatch, "AGENT_BOM_REQUIRE_TENANT_BOUNDARY", UNSET)
    _set(monkeypatch, "AGENT_BOM_CONTROL_PLANE_REPLICAS", raw)
    assert _tenant._multi_tenant_signals_present() is expected


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, "default"), ("", "default"), ("  ", "default"), (" acme ", "acme")])
def test_cli_tenant_env_resolution(monkeypatch, raw, expected):
    from agent_bom.cli import _tenant

    _set(monkeypatch, "AGENT_BOM_REQUIRE_TENANT_BOUNDARY", UNSET)
    _set(monkeypatch, "AGENT_BOM_CONTROL_PLANE_REPLICAS", UNSET)
    _set(monkeypatch, "AGENT_BOM_TENANT_ID", raw)
    assert _tenant.resolve_cli_tenant_id() == expected
    assert _tenant.resolve_cli_tenant_id_strict() == expected


def test_cli_findings_client_env_fallbacks(monkeypatch):
    from agent_bom.cli import _findings_group

    for name in ("AGENT_BOM_API_URL", "AGENT_BOM_API_KEY", "AGENT_BOM_API_TOKEN", "AGENT_BOM_TENANT_ID"):
        _set(monkeypatch, name, UNSET)
    client = _findings_group._make_client(None, None, None, None)
    assert client.base_url.rstrip("/") == "http://127.0.0.1:8422"
    assert not client.api_key and not client.bearer_token and not client.tenant_id
    _set(monkeypatch, "AGENT_BOM_API_URL", "https://cp.example.test")
    _set(monkeypatch, "AGENT_BOM_API_KEY", "k")
    _set(monkeypatch, "AGENT_BOM_TENANT_ID", "t")
    client = _findings_group._make_client(None, None, None, None)
    assert (client.base_url.rstrip("/"), client.api_key, client.tenant_id) == ("https://cp.example.test", "k", "t")
    assert _findings_group._make_client("https://x.example.test", "k2", None, "t2").api_key == "k2"


def test_cli_profiles_env(monkeypatch, tmp_path):
    from agent_bom.cli import _profiles

    _set(monkeypatch, _profiles.CONFIG_ENV_VAR, UNSET)
    assert _profiles.default_config_path() == _profiles.DEFAULT_CONFIG_PATH.expanduser()
    _set(monkeypatch, _profiles.CONFIG_ENV_VAR, str(tmp_path / "c.yaml"))
    assert _profiles.default_config_path() == tmp_path / "c.yaml"
    _set(monkeypatch, _profiles.PROFILE_ENV_VAR, " prod ")
    assert _profiles.resolve_profile_name(None, {"current_profile": "dev"}) == "prod"
    _set(monkeypatch, _profiles.PROFILE_ENV_VAR, "")
    assert _profiles.resolve_profile_name(None, {"current_profile": "dev"}) == "dev"
    _set(monkeypatch, _profiles.TENANT_ENV_VAR, "existing")
    _profiles.apply_profile_environment({"tenant_id": "from-profile"})
    assert os.environ[_profiles.TENANT_ENV_VAR] == "existing"
    _set(monkeypatch, _profiles.TENANT_ENV_VAR, "")
    _profiles.apply_profile_environment({"tenant_id": "from-profile"})
    assert os.environ[_profiles.TENANT_ENV_VAR] == "from-profile"
    profile = {"api_url_env": "AGENT_BOM_TEST_PROFILE_REF"}
    _set(monkeypatch, "AGENT_BOM_TEST_PROFILE_REF", "from-env")
    assert _profiles.profile_env_default(None, profile, "api_url", "cur", "api_url_env") == "from-env"
    _set(monkeypatch, "AGENT_BOM_TEST_PROFILE_REF", "")
    assert _profiles.profile_env_default(None, profile, "api_url", "cur", "api_url_env") == "cur"


@pytest.mark.parametrize(("raw", "enabled", "expected"), [(UNSET, False, None), (UNSET, True, 0), ("10", False, 10), (" 10 ", True, 10)])
def test_scan_reproducible_timestamp(monkeypatch, raw, enabled, expected):
    from agent_bom.cli.agents.scan_pipeline import helpers

    _set(monkeypatch, "SOURCE_DATE_EPOCH", raw)
    result = helpers._reproducible_generated_at(enabled)
    assert (result if result is None else int(result.timestamp())) == expected


@pytest.mark.parametrize("raw", ["", "soon"])
def test_scan_reproducible_timestamp_rejects_malformed(monkeypatch, raw):
    from agent_bom.cli.agents.scan_pipeline import helpers

    _set(monkeypatch, "SOURCE_DATE_EPOCH", raw)
    with pytest.raises(click.ClickException, match="SOURCE_DATE_EPOCH"):
        helpers._reproducible_generated_at(False)


def test_scan_cloud_scope_env_fallbacks(monkeypatch):
    from agent_bom.cli.agents.scan_pipeline import helpers

    for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AZURE_SUBSCRIPTION_ID", "GOOGLE_CLOUD_PROJECT"):
        _set(monkeypatch, name, UNSET)
    _set(monkeypatch, "AWS_REGION", "")
    _set(monkeypatch, "AWS_DEFAULT_REGION", "us-east-2")
    _set(monkeypatch, "GOOGLE_CLOUD_PROJECT", "proj")
    scope = helpers._cloud_scan_scope(
        providers=["aws", "gcp", "azure"], aws_region=None, aws_profile=None, azure_subscription=None, gcp_project=None
    )
    assert scope["aws"] == {"region": "us-east-2"}
    assert scope["gcp"] == {"project": "proj"}
    assert scope["azure"] == {}
    scope = helpers._cloud_scan_scope(providers=["aws"], aws_region="eu-west-1", aws_profile="p", azure_subscription=None, gcp_project=None)
    assert scope["aws"] == {"profile": "p", "region": "eu-west-1"}


# ── proxy_audit / proxy_policy / siem.ocsf ──────────────────────────────────


@pytest.mark.parametrize(("raw", "expected"), [*FLAG_TABLE, ("enabled", True), (" Enabled ", True)])
def test_proxy_audit_flag(monkeypatch, raw, expected):
    from agent_bom import proxy_audit

    _set(monkeypatch, "AGENT_BOM_TEST_FLAG", raw)
    assert proxy_audit._env_flag_enabled("AGENT_BOM_TEST_FLAG") is expected


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, 5), ("", 5), ("0", 1), ("-4", 1), (" 7 ", 7), ("x", 5)])
def test_proxy_audit_positive_int(monkeypatch, raw, expected):
    from agent_bom import proxy_audit

    _set(monkeypatch, "AGENT_BOM_TEST_INT", raw)
    assert proxy_audit._env_positive_int("AGENT_BOM_TEST_INT", 5) == expected


@pytest.mark.parametrize(
    ("raw", "expected"), [(UNSET, "closed"), ("", "closed"), (" OPEN ", "open"), ("closed", "closed"), ("bogus", "closed"), ("0", "closed")]
)
def test_proxy_policy_fail_mode(monkeypatch, raw, expected):
    from agent_bom import proxy_policy

    _set(monkeypatch, proxy_policy.GATEWAY_FAIL_MODE_ENV, raw)
    assert proxy_policy.resolve_fail_mode() == expected
    assert proxy_policy.resolve_fail_mode("open") == "open"


@pytest.mark.parametrize(("raw", "expected"), [(UNSET, "0.0.0"), ("1.2.3", "1.2.3")])
def test_ocsf_syslog_product_version(monkeypatch, raw, expected):
    from types import SimpleNamespace

    from agent_bom.siem.ocsf import SyslogConnector

    _set(monkeypatch, "AGENT_BOM_VERSION", raw)
    connector = SyslogConnector(SimpleNamespace(url="syslog.example.test:514"))
    assert connector._product_version == expected


# ── ai_enrich.py ────────────────────────────────────────────────────────────

AI_ENV = ("LITELLM_PROXY_URL", "LITELLM_API_KEY", "OPENAI_API_BASE", "OPENAI_BASE_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HF_TOKEN")


@pytest.fixture
def clean_ai_env(monkeypatch):
    for name in AI_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("env", "model", "ready"),
    [
        ({}, "openai/gpt-4o-mini", False),
        ({"OPENAI_API_KEY": "k"}, "openai/gpt-4o-mini", True),
        ({"OPENAI_API_KEY": ""}, "openai/gpt-4o-mini", False),
        ({"OPENAI_API_BASE": " http://127.0.0.1:4000 "}, "openai/local", True),
        ({"OPENAI_BASE_URL": "http://localhost:4000"}, "openai/local", True),
        ({"OPENAI_API_BASE": "https://api.example.test"}, "openai/local", False),
        ({"LITELLM_PROXY_URL": " http://127.0.0.1:4000 "}, "anything", True),
        ({"LITELLM_PROXY_URL": "https://proxy.example.test"}, "anything", False),
        ({"LITELLM_PROXY_URL": "https://proxy.example.test", "LITELLM_API_KEY": "k"}, "anything", True),
        ({"LITELLM_PROXY_URL": ""}, "bedrock/claude", True),
    ],
)
def test_ai_litellm_readiness(monkeypatch, clean_ai_env, env, model, ready):
    from agent_bom import ai_enrich

    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert ai_enrich._litellm_readiness(model)[0] is ready


@pytest.mark.parametrize(("raw", "configured"), [(UNSET, False), ("", False), ("hf_x", True)])
def test_ai_huggingface_token_presence(monkeypatch, clean_ai_env, raw, configured):
    from agent_bom import ai_enrich

    monkeypatch.setattr(ai_enrich, "_check_huggingface", lambda: True)
    _set(monkeypatch, "HF_TOKEN", raw)
    assert ai_enrich._provider_status("huggingface").configured is configured
    assert ai_enrich.HuggingFaceProvider().is_available() is configured
