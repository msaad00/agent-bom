"""Structural tests for deploy/docker-compose*.yml.

Closes #1962 (the verification piece). These tests pin two contracts so a
future compose edit cannot regress silently:

1. Every long-lived service in every compose file declares a healthcheck
   pointed at /health (API/proxy) or its image's native readiness probe
   (postgres pg_isready, redis ping, ui HTTP root). One-shot scanner
   commands and stdio-only sidecars are exempt and listed by name.
2. The production-shaped docker-compose.platform.yml uses Docker secrets
   for the Postgres admin password (POSTGRES_PASSWORD_FILE plus a
   top-level secrets: block) instead of raw env passthrough.
3. Every compose file carries a "Profile:" header marker so operators can
   tell pilot/dev/production apart at a glance.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_DIR = ROOT / "deploy"
ENV_EXAMPLE = ROOT / ".env.example"

# Services that intentionally have no healthcheck — keep this list short and
# explain each. Anything else missing a healthcheck fails the test.
HEALTHCHECK_EXEMPT: dict[str, set[str]] = {
    "docker-compose.yml": {
        # Scanner runs as a one-shot `agent-bom scan ...` command and exits;
        # depends_on uses postgres healthcheck for ordering.
        "agent-bom",
    },
    "docker-compose.runtime-example.yml": {
        # The mcp-server container talks stdio to the proxy and never opens a
        # TCP listener — there is no port to probe.
        "mcp-server",
    },
    "docker-compose.hosted-poc.yml": {
        # Overlay applied on top of docker-compose.platform.yml; it only sets
        # hosted-specific environment. Healthchecks are defined once in the
        # base platform compose and inherited at merge time.
        "api",
    },
    "docker-compose.product.yml": {
        # Overlay applied on top of docker-compose.platform.yml; it only sets
        # authenticated-product environment. Healthchecks are defined once in
        # the base platform compose and inherited at merge time.
        "api",
    },
}


def _compose_files() -> list[Path]:
    return sorted(COMPOSE_DIR.glob("docker-compose*.yml"))


@pytest.mark.parametrize("path", _compose_files(), ids=lambda p: p.name)
def test_every_long_lived_service_has_a_healthcheck(path: Path) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    exempt = HEALTHCHECK_EXEMPT.get(path.name, set())
    missing = [name for name, service in services.items() if name not in exempt and not (service or {}).get("healthcheck")]
    assert not missing, (
        f"{path.name}: services without a healthcheck: {missing}. "
        "Add a healthcheck or list the service in HEALTHCHECK_EXEMPT with a reason."
    )


def test_platform_compose_uses_docker_secrets_for_postgres_password() -> None:
    path = COMPOSE_DIR / "docker-compose.platform.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    secrets_block = data.get("secrets") or {}
    assert "postgres_password" in secrets_block, (
        "docker-compose.platform.yml must declare a top-level secrets: block with a postgres_password entry sourced from a file mount."
    )
    assert "postgres_app_password" in secrets_block, (
        "platform compose must also declare postgres_app_password for the DML-only agent_bom_app role."
    )
    secret_file = secrets_block["postgres_password"].get("file")
    assert secret_file, (
        "postgres_password secret must be file-sourced (file: ./secrets/postgres_password) so docker-compose binds it read-only."
    )
    assert str(secret_file).endswith("postgres_password}"), (
        "platform compose must default to the real deploy/secrets/postgres_password "
        "path so shared stacks fail closed when the operator has not mounted a secret."
    )

    postgres = (data.get("services") or {}).get("postgres") or {}
    env = postgres.get("environment") or {}
    if isinstance(env, list):
        env = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in env if "=" in item}
    assert env.get("POSTGRES_PASSWORD_FILE") == "/run/secrets/postgres_password", (
        "platform postgres must read POSTGRES_PASSWORD_FILE from the mounted secret so the password never appears in docker inspect output."
    )
    assert env.get("POSTGRES_APP_PASSWORD_FILE") == "/run/secrets/postgres_app_password"
    # The raw POSTGRES_PASSWORD env passthrough must NOT coexist with the
    # file-based variant — if both are set, the postgres image picks the
    # plain one and the secret is silently bypassed.
    assert "POSTGRES_PASSWORD" not in env, (
        "platform postgres must use POSTGRES_PASSWORD_FILE only; remove the raw "
        "POSTGRES_PASSWORD env passthrough so the secret is enforced."
    )
    assert "POSTGRES_APP_PASSWORD" not in env

    assert "postgres_password" in (postgres.get("secrets") or []), (
        "platform postgres service must list postgres_password under its secrets: block so the file mount is created."
    )
    assert "postgres_app_password" in (postgres.get("secrets") or [])

    api = (data.get("services") or {}).get("api") or {}
    api_env = api.get("environment") or []
    api_map = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in api_env if isinstance(item, str) and "=" in item}
    assert api_map.get("AGENT_BOM_POSTGRES_URL", "").startswith("postgresql://agent_bom_app@")
    assert api_map.get("AGENT_BOM_POSTGRES_PASSWORD_FILE") == "/run/secrets/postgres_app_password"
    assert "postgres_app_password" in (api.get("secrets") or [])


def test_env_example_does_not_store_postgres_passwords() -> None:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    env_values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env_values[key] = value

    assert "POSTGRES_PASSWORD" not in env_values
    assert "POSTGRES_APP_PASSWORD" not in env_values
    assert "Do NOT put Postgres passwords" in text

    for name in ("postgres_password.example", "postgres_app_password.example"):
        placeholder = COMPOSE_DIR / "secrets" / name
        assert placeholder.exists(), f"documented placeholder must remain available: {name}"
        assert "REPLACE_ME" in placeholder.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "compose_name",
    ("docker-compose.yml", "docker-compose.fullstack.yml", "docker-compose.platform.yml"),
)
def test_compose_stacks_never_interpolate_postgres_passwords(compose_name: str) -> None:
    path = COMPOSE_DIR / compose_name
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    assert "${POSTGRES_PASSWORD}" not in text
    assert "${POSTGRES_PASSWORD:?" not in text
    assert "${POSTGRES_APP_PASSWORD}" not in text
    assert "${POSTGRES_APP_PASSWORD:?" not in text
    assert "${POSTGRES_APP_PASSWORD:-" not in text
    # Path overrides for secret *files* are allowed (POSTGRES_PASSWORD_FILE).
    assert "POSTGRES_PASSWORD_FILE" in text
    assert "POSTGRES_APP_PASSWORD_FILE" in text or "postgres_app_password" in text

    services = data.get("services") or {}
    for name, service in services.items():
        env = service.get("environment") or {}
        if isinstance(env, list):
            env = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in env if isinstance(item, str) and "=" in item}
        assert "POSTGRES_PASSWORD" not in env, f"{compose_name}:{name} must not set POSTGRES_PASSWORD"
        assert "POSTGRES_APP_PASSWORD" not in env, f"{compose_name}:{name} must not set POSTGRES_APP_PASSWORD"
        for key, value in env.items():
            if key == "AGENT_BOM_POSTGRES_URL":
                assert value.startswith("postgresql://agent_bom_app@"), (
                    f"{compose_name}:{name} must connect as agent_bom_app without an embedded password"
                )


def test_platform_api_fails_closed_for_auth_docs_and_local_scans() -> None:
    path = COMPOSE_DIR / "docker-compose.platform.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    api = (data.get("services") or {}).get("api") or {}
    env = api.get("environment") or []
    env_map = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in env if isinstance(item, str) and "=" in item}

    assert env_map.get("AGENT_BOM_API_KEY_FILE") == "/run/secrets/api_key"
    assert env_map.get("AGENT_BOM_AUDIT_HMAC_KEY_FILE") == "/run/secrets/audit_hmac_key"
    assert env_map.get("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_FILE") == "/run/secrets/browser_session_signing_key"
    assert env_map.get("AGENT_BOM_CONNECTIONS_KEY_FILE") == "/run/secrets/connections_key"
    assert "AGENT_BOM_API_KEY" not in env_map
    assert "AGENT_BOM_OIDC_ISSUER" in env_map
    assert "--allow-insecure-no-auth" not in api.get("command", "")
    assert env_map.get("AGENT_BOM_DISABLE_DOCS") == "1"
    assert env_map.get("AGENT_BOM_API_LOCAL_PATH_SCANS") == "disabled"
    assert env_map.get("AGENT_BOM_SESSION_COOKIE_SECURE") == "${AGENT_BOM_SESSION_COOKIE_SECURE:-1}"
    assert api.get("ports") == ["${AGENT_BOM_API_BIND_HOST:-127.0.0.1}:${API_PORT:-8422}:8422"]
    secrets = set(api.get("secrets") or [])
    assert {"api_key", "audit_hmac_key", "browser_session_signing_key", "connections_key"} <= secrets


def test_platform_ui_binds_loopback_by_default() -> None:
    path = COMPOSE_DIR / "docker-compose.platform.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    ui = (data.get("services") or {}).get("ui") or {}

    assert ui.get("ports") == ["${AGENT_BOM_UI_BIND_HOST:-127.0.0.1}:${UI_PORT:-3000}:3000"]


def test_fullstack_is_loopback_only_auth_required_and_matches_runtime_user_home() -> None:
    path = COMPOSE_DIR / "docker-compose.fullstack.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    api = (data.get("services") or {}).get("api") or {}
    env = api.get("environment") or {}

    assert "--allow-insecure-no-auth" not in api.get("command", "")
    assert env.get("AGENT_BOM_API_KEY_FILE") == "/run/secrets/api_key"
    assert "AGENT_BOM_API_KEY" not in env
    assert env.get("AGENT_BOM_POSTGRES_URL", "").startswith("postgresql://agent_bom_app@")
    assert env.get("AGENT_BOM_POSTGRES_PASSWORD_FILE") == "/run/secrets/postgres_app_password"
    assert api.get("ports") == ["127.0.0.1:${API_PORT:-8422}:8422"]
    assert "~/.config:/home/abom/.config:ro" in (api.get("volumes") or [])
    assert "~/.claude:/home/abom/.claude:ro" in (api.get("volumes") or [])
    assert "api_key" in (api.get("secrets") or [])
    assert "postgres_app_password" in (api.get("secrets") or [])
    assert "postgres_password" in ((data.get("secrets") or {}))
    assert "postgres_app_password" in ((data.get("secrets") or {}))
    assert "api_key" in ((data.get("secrets") or {}))


@pytest.mark.parametrize(
    "compose_name",
    ("docker-compose.fullstack.yml", "docker-compose.platform.yml"),
)
def test_compose_stacks_never_interpolate_control_plane_secrets(compose_name: str) -> None:
    path = COMPOSE_DIR / compose_name
    text = path.read_text(encoding="utf-8")
    for name in (
        "AGENT_BOM_API_KEY",
        "AGENT_BOM_AUDIT_HMAC_KEY",
        "AGENT_BOM_CONNECTIONS_KEY",
        "AGENT_BOM_BROWSER_SESSION_SIGNING_KEY",
    ):
        assert f"${{{name}" not in text, f"{compose_name} must not interpolate {name}"
        assert f"{name}_FILE" in text, f"{compose_name} must set {name}_FILE"

def test_hosted_poc_overlay_keeps_api_and_ui_loopback_only() -> None:
    path = COMPOSE_DIR / "docker-compose.hosted-poc.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    services = data.get("services") or {}

    api_env = services["api"]["environment"]
    assert "ports" not in services["api"]
    assert "ui" not in services
    assert api_env == [
        "AGENT_BOM_SESSION_COOKIE_SECURE=1",
        "AGENT_BOM_DEMO_ESTATE=1",
        "AGENT_BOM_NO_AUTH_ROLE=viewer",
    ]


def test_active_docker_docs_do_not_mount_config_under_root_home() -> None:
    active_docs = [
        ROOT / "docs" / "DEPLOYMENT.md",
        ROOT / "docs" / "ENTERPRISE_DEPLOYMENT.md",
        ROOT / "docs" / "MCP_SERVER.md",
        ROOT / "site-docs" / "getting-started" / "install.md",
        ROOT / "site-docs" / "deployment" / "docker.md",
        COMPOSE_DIR / "docker-compose.yml",
        COMPOSE_DIR / "docker-compose.fullstack.yml",
    ]
    offenders = [str(path.relative_to(ROOT)) for path in active_docs if "/root/.config" in path.read_text(encoding="utf-8")]
    assert not offenders


@pytest.mark.parametrize("path", _compose_files(), ids=lambda p: p.name)
def test_compose_file_declares_profile_header(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    # Header lives in the first ~20 lines and is rendered as
    # ``# ── Profile: <NAME> ──`` to make pilot/dev/production obvious.
    head = "\n".join(text.splitlines()[:20])
    assert "Profile:" in head, (
        f"{path.name}: missing `# ── Profile: <NAME> ──` header in the first 20 "
        "lines. Operators rely on this to tell pilot/dev/production-shaped "
        "files apart at a glance."
    )
