#!/usr/bin/env python3
"""Generate release evidence for gateway/proxy/runtime readiness.

The output is intentionally machine-readable JSON so release notes can cite a
stable artifact while the script remains runnable before each release.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from starlette.testclient import TestClient

from agent_bom.api.metrics import reset_for_tests as reset_metrics
from agent_bom.audit_replay import verify_hash_chain
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy_audit import write_audit_record
from agent_bom.proxy_sandbox import SandboxConfig, build_sandboxed_command

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "release" / "runtime-evidence-v0.86.3.json"
DOCKER_IMAGE = "agent-bom-runtime-evidence:0.86.3"
GATEWAY_TOKEN = "release-gateway-token-with-32-plus-bytes"
UPSTREAM_TOKEN_ENV = "AGENT_BOM_RELEASE_UPSTREAM_TOKEN"
UPSTREAM_TOKEN_VALUE = "release-upstream-token-with-32-plus-bytes"


def _git_value(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except Exception:
        return "unknown"
    return result.stdout.strip() or "unknown"


def _display_command(command: list[str], tmp_path: Path) -> list[str]:
    """Return the executed command with machine-local temp paths normalized."""
    return ["<tmpdir>:/evidence" if part == f"{tmp_path}:/evidence" else part for part in command]


def _gateway_evidence() -> dict[str, Any]:
    reset_metrics()
    os.environ[UPSTREAM_TOKEN_ENV] = UPSTREAM_TOKEN_VALUE
    audit_events: list[dict[str, Any]] = []
    upstream_calls: list[dict[str, Any]] = []

    async def audit_sink(event: dict[str, Any]) -> None:
        audit_events.append(event)

    async def fake_upstream(upstream: UpstreamConfig, message: dict[str, Any], extra_headers: dict[str, str]) -> dict[str, Any]:
        auth_headers = await upstream.resolve_auth_headers()
        upstream_calls.append(
            {
                "upstream": upstream.name,
                "tool": message.get("params", {}).get("name"),
                "auth_header_present": "Authorization" in auth_headers,
                "traceparent_present": "traceparent" in extra_headers,
            }
        )
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"ok": True}}

    registry = UpstreamRegistry(
        [
            UpstreamConfig(
                name="jira",
                url="https://mcp.jira.example.com/mcp",
                transport="streamable-http",
                auth="bearer",
                token_env=UPSTREAM_TOKEN_ENV,
            )
        ]
    )
    policy = {"rules": [{"id": "release-no-shell", "action": "block", "block_tools": ["run_shell"]}]}
    settings = GatewaySettings(
        registry=registry,
        policy=policy,
        audit_sink=audit_sink,
        upstream_caller=fake_upstream,
        bearer_token=GATEWAY_TOKEN,
    )

    with TestClient(create_gateway_app(settings)) as client:
        health = client.get("/healthz")
        unauth = client.post(
            "/mcp/jira",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "query_issues", "arguments": {}}},
        )
        blocked = client.post(
            "/mcp/jira",
            headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_shell", "arguments": {"command": "id"}}},
        )
        allowed = client.post(
            "/mcp/jira",
            headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "query_issues", "arguments": {"jql": "project = AGENTBOM"}},
            },
        )
        metrics = client.get("/metrics", headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"})

    os.environ.pop(UPSTREAM_TOKEN_ENV, None)
    metric_lines = [line for line in metrics.text.splitlines() if "agent_bom_gateway_relays_total" in line]
    return {
        "healthz": {
            "status_code": health.status_code,
            "status": health.json().get("status"),
            "incoming_token_required": health.json().get("auth", {}).get("incoming_token_required"),
            "upstreams": health.json().get("upstreams"),
            "policy_source_kind": health.json().get("policy_runtime", {}).get("source_kind"),
        },
        "bearer_auth": {
            "missing_token_status_code": unauth.status_code,
            "valid_token_forwarded_status_code": allowed.status_code,
        },
        "policy_block": {
            "status_code": blocked.status_code,
            "jsonrpc_error_code": blocked.json().get("error", {}).get("code"),
            "audit_actions": [event.get("action") for event in audit_events],
        },
        "metrics": {
            "status_code": metrics.status_code,
            "content_type": metrics.headers.get("content-type"),
            "relay_lines": metric_lines,
        },
        "upstream_auth": {
            "bearer_header_resolved_from_env": bool(upstream_calls and upstream_calls[0]["auth_header_present"]),
            "traceparent_forwarded": bool(upstream_calls and upstream_calls[0]["traceparent_present"]),
        },
        "gateway_limit": {
            "supported_upstream_transport": "streamable-http request/response JSON-RPC over HTTP POST",
            "not_supported_in_gateway": ["persistent SSE relay", "stdio relay"],
            "stdio_path": "use per-MCP agent-bom proxy wrappers",
            "source": "src/agent_bom/gateway_server.py MVP scope and docs/design/MULTI_MCP_GATEWAY.md",
        },
    }


def _proxy_sandbox_evidence() -> dict[str, Any]:
    pinned_image = "ghcr.io/acme/mcp-sandbox:1@sha256:" + "a" * 64
    command, sandbox_evidence = build_sandboxed_command(
        ["python", "-c", "print('ok')"],
        SandboxConfig(enabled=True, runtime="docker", image=pinned_image, image_pin_policy="enforce"),
        resolve_runtime=False,
    )

    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "proxy-audit.jsonl"
        with audit_path.open("w", encoding="utf-8") as log_file:
            first = write_audit_record(
                log_file,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "type": "mcp_execution_posture",
                    "execution_posture": {
                        "mode": "container_isolated",
                        "sandbox_evidence": sandbox_evidence,
                    },
                },
            )
            second = write_audit_record(
                log_file,
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "type": "tools/call",
                    "tool": "blocked_tool",
                    "policy": "blocked",
                    "reason_code": "undeclared_tool",
                },
            )
        verified, tampered = verify_hash_chain(audit_path)

    return {
        "sandbox_command_prefix": command[:12],
        "sandbox_evidence": sandbox_evidence,
        "audit_chain": {
            "records_written": 2,
            "verified": verified,
            "tampered": tampered,
            "first_record_hash_present": bool(first.get("record_hash")),
            "second_prev_hash_matches_first": second.get("prev_hash") == first.get("record_hash"),
        },
    }


def _docker_smoke() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        build = subprocess.run(
            ["docker", "build", "-f", "deploy/docker/Dockerfile.runtime", "-t", DOCKER_IMAGE, "."],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
        )
        if build.returncode != 0:
            return {
                "ran": True,
                "image": DOCKER_IMAGE,
                "build_returncode": build.returncode,
                "build_tail": build.stdout.splitlines()[-40:],
            }

        stdin_payload = "\n".join(
            [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "blocked_tool", "arguments": {}}}),
                "",
            ]
        )
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "-v",
            f"{tmp_path}:/evidence",
            "-e",
            "AGENT_BOM_RUNTIME_SMOKE_ONESHOT=1",
            DOCKER_IMAGE,
            "--no-isolate",
            "--log",
            "/evidence/audit.jsonl",
            "--block-undeclared",
            "--",
            "python",
            "-m",
            "agent_bom.runtime_smoke_mcp",
        ]
        try:
            run = subprocess.run(
                command,
                cwd=REPO_ROOT,
                input=stdin_payload,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "ran": True,
                "image": DOCKER_IMAGE,
                "build_returncode": build.returncode,
                "run_returncode": "timeout",
                "command": _display_command(command, tmp_path),
                "stdout_lines": (exc.stdout or "").splitlines() if isinstance(exc.stdout, str) else [],
                "stderr_tail": ((exc.stderr or "").splitlines() if isinstance(exc.stderr, str) else [])[-20:],
                "audit_record_count": 0,
                "audit_contains_execution_posture": False,
                "audit_contains_blocked_call": False,
            }
        audit_path = tmp_path / "audit.jsonl"
        audit_records = audit_path.read_text(encoding="utf-8").splitlines() if audit_path.exists() else []
        return {
            "ran": True,
            "image": DOCKER_IMAGE,
            "build_returncode": build.returncode,
            "run_returncode": run.returncode,
            "command": _display_command(command, tmp_path),
            "stdout_lines": run.stdout.splitlines(),
            "stderr_tail": run.stderr.splitlines()[-20:],
            "audit_record_count": len(audit_records),
            "audit_contains_execution_posture": any("mcp_execution_posture" in line for line in audit_records),
            "audit_contains_blocked_call": any("blocked" in line for line in audit_records),
        }


def generate(*, include_docker: bool) -> dict[str, Any]:
    evidence = {
        "schema": "agent-bom-runtime-release-evidence/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_value("rev-parse", "HEAD"),
        "git_branch": _git_value("branch", "--show-current"),
        "gateway": _gateway_evidence(),
        "proxy_sandbox": _proxy_sandbox_evidence(),
    }
    evidence["docker_runtime_proxy_smoke"] = (
        _docker_smoke()
        if include_docker
        else {
            "ran": False,
            "reason": "pass --docker-smoke to build and run the runtime proxy image",
            "expected_image": DOCKER_IMAGE,
        }
    )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--docker-smoke", action="store_true", help="Build and run the runtime proxy Docker image smoke.")
    args = parser.parse_args()

    evidence = generate(include_docker=args.docker_smoke)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
