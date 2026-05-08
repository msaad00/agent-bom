from __future__ import annotations

from scripts.generate_runtime_evidence_pack import generate


def test_runtime_evidence_pack_covers_release_gate_without_docker() -> None:
    evidence = generate(include_docker=False)

    assert evidence["schema"] == "agent-bom-runtime-release-evidence/v1"

    gateway = evidence["gateway"]
    assert gateway["healthz"] == {
        "status_code": 200,
        "status": "ok",
        "incoming_token_required": True,
        "upstreams": ["jira"],
        "policy_source_kind": "inline",
    }
    assert gateway["bearer_auth"]["missing_token_status_code"] == 401
    assert gateway["bearer_auth"]["valid_token_forwarded_status_code"] == 200
    assert gateway["policy_block"]["status_code"] == 200
    assert gateway["policy_block"]["jsonrpc_error_code"] == -32001
    assert gateway["policy_block"]["audit_actions"] == [
        "gateway.policy_blocked",
        "gateway.tool_call",
    ]
    assert gateway["upstream_auth"] == {
        "bearer_header_resolved_from_env": True,
        "traceparent_forwarded": True,
    }
    assert gateway["metrics"]["status_code"] == 200
    assert any('outcome="blocked"' in line for line in gateway["metrics"]["relay_lines"])
    assert any('outcome="forwarded"' in line for line in gateway["metrics"]["relay_lines"])
    assert gateway["gateway_limit"]["supported_upstream_transport"] == ("streamable-http request/response JSON-RPC over HTTP POST")
    assert "stdio relay" in gateway["gateway_limit"]["not_supported_in_gateway"]

    proxy_sandbox = evidence["proxy_sandbox"]
    assert proxy_sandbox["sandbox_command_prefix"][:2] == [
        proxy_sandbox["sandbox_evidence"]["runtime"],
        "run",
    ]
    assert proxy_sandbox["sandbox_evidence"]["enabled"] is True
    assert proxy_sandbox["sandbox_evidence"]["read_only_rootfs"] is True
    assert proxy_sandbox["sandbox_evidence"]["egress_policy"] == "deny"
    assert proxy_sandbox["sandbox_evidence"]["drop_capabilities"] is True
    assert proxy_sandbox["sandbox_evidence"]["no_new_privileges"] is True
    assert proxy_sandbox["sandbox_evidence"]["image_pin_policy"] == "enforce"
    assert proxy_sandbox["sandbox_evidence"]["image_pinned"] is True
    assert proxy_sandbox["audit_chain"] == {
        "records_written": 2,
        "verified": 2,
        "tampered": 0,
        "first_record_hash_present": True,
        "second_prev_hash_matches_first": True,
    }

    assert evidence["docker_runtime_proxy_smoke"] == {
        "ran": False,
        "reason": "pass --docker-smoke to build and run the runtime proxy image",
        "expected_image": "agent-bom-runtime-evidence:0.86.3",
    }
