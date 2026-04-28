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

# Services that intentionally have no healthcheck — keep this list short and
# explain each. Anything else missing a healthcheck fails the test.
HEALTHCHECK_EXEMPT: dict[str, set[str]] = {
    "docker-compose.yml": {
        # Scanner runs as a one-shot `agent-bom scan ...` command and exits;
        # depends_on uses postgres healthcheck for ordering.
        "agent-bom",
    },
    "docker-compose.runtime.yml": {
        # The mcp-server container talks stdio to the proxy and never opens a
        # TCP listener — there is no port to probe.
        "mcp-server",
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
    assert "file" in secrets_block["postgres_password"], (
        "postgres_password secret must be file-sourced (file: ./secrets/postgres_password) so docker-compose binds it read-only."
    )

    postgres = (data.get("services") or {}).get("postgres") or {}
    env = postgres.get("environment") or {}
    if isinstance(env, list):
        env = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in env if "=" in item}
    assert env.get("POSTGRES_PASSWORD_FILE") == "/run/secrets/postgres_password", (
        "platform postgres must read POSTGRES_PASSWORD_FILE from the mounted secret so the password never appears in docker inspect output."
    )
    # The raw POSTGRES_PASSWORD env passthrough must NOT coexist with the
    # file-based variant — if both are set, the postgres image picks the
    # plain one and the secret is silently bypassed.
    assert "POSTGRES_PASSWORD" not in env, (
        "platform postgres must use POSTGRES_PASSWORD_FILE only; remove the raw "
        "POSTGRES_PASSWORD env passthrough so the secret is enforced."
    )

    assert "postgres_password" in (postgres.get("secrets") or []), (
        "platform postgres service must list postgres_password under its secrets: block so the file mount is created."
    )


def test_platform_api_fails_closed_for_auth_docs_and_local_scans() -> None:
    path = COMPOSE_DIR / "docker-compose.platform.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    api = (data.get("services") or {}).get("api") or {}
    env = api.get("environment") or []
    env_map = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in env if isinstance(item, str) and "=" in item}

    assert "AGENT_BOM_API_KEY" in env_map
    assert "AGENT_BOM_OIDC_ISSUER" in env_map
    assert "--allow-insecure-no-auth" not in api.get("command", "")
    assert env_map.get("AGENT_BOM_DISABLE_DOCS") == "1"
    assert env_map.get("AGENT_BOM_API_LOCAL_PATH_SCANS") == "disabled"


def test_fullstack_is_loopback_only_and_matches_runtime_user_home() -> None:
    path = COMPOSE_DIR / "docker-compose.fullstack.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    api = (data.get("services") or {}).get("api") or {}

    assert "--allow-insecure-no-auth" in api.get("command", "")
    assert api.get("ports") == ["127.0.0.1:${API_PORT:-8422}:8422"]
    assert "~/.config:/home/abom/.config:ro" in (api.get("volumes") or [])
    assert "~/.claude:/home/abom/.claude:ro" in (api.get("volumes") or [])


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
