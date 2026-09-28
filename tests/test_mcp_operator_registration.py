"""Characterize operator tool registration and the authenticated dispatch boundary."""

import asyncio
import inspect

import pytest

from agent_bom.mcp_server_operator_tools import register_operator_tools

# Public order, annotation and dispatch scopes before registration extraction.
CONTRACTS = [
    ("graph_correlate", "write_idempotent", "scan:write", True),
    ("graph_correlation_status", "read_only", "graph:read", False),
    ("diff", "write_action", "findings:write", True),
    ("findings_triage", "write_action", "findings:write", True),
    ("list_exceptions", "read_only", None, False),
    ("request_exception", "write_action", "findings:write", True),
    ("approve_exception", "write_action", "findings:write", True),
    ("risk_campaign_workflow", "write_action", "findings:write", True),
    ("cloud_side_scan", "write_action", "cloud:write", True),
    ("marketplace_check", "read_only", None, False),
    ("code_scan", "read_only", None, False),
    ("context_graph", "read_only", None, False),
    ("graph_export", "read_only", None, False),
    ("analytics_query", "read_only", None, False),
    ("cis_benchmark", "read_only", None, False),
    ("kspm_cluster_posture", "read_only", None, False),
    ("fleet_scan", "read_only", None, False),
    ("runtime_correlate", "read_only", None, False),
    ("runtime_production_index", "read_only", None, False),
    ("runtime_blueprints", "read_only", None, False),
    ("runtime_blueprint_drift", "read_only", None, False),
    ("cost_report", "read_only", None, False),
    ("anomaly_scan", "read_only", None, False),
    ("drift_incidents", "read_only", None, False),
    ("proxy_status", "read_only", None, False),
    ("proxy_alerts", "read_only", None, False),
    ("gateway_status", "read_only", None, False),
    ("shield_status", "read_only", None, False),
    ("shield_start", "write_action", "shield:write", True),
    ("shield_unblock", "write_action", "shield:write", True),
    ("shield_break_glass", "write_action", "shield:write", True),
    ("identity_issue", "write_action", "identity:write", True),
    ("identity_rotate", "write_action", "identity:write", True),
    ("identity_revoke", "write_action", "identity:write", True),
    ("identity_grant_jit", "write_action", "identity:write", True),
    ("identity_revoke_jit", "write_action", "identity:write", True),
    ("firewall_check", "read_only", None, False),
    ("audit_query", "read_only", None, False),
    ("audit_integrity", "read_only", None, False),
    ("cost_forecast", "read_only", None, False),
    ("cost_allocation", "read_only", None, False),
    ("credential_expiry", "read_only", None, False),
    ("nhi_discover", "read_only", None, False),
    ("cloud_inventory", "read_only", None, False),
    ("access_review", "write_idempotent", "identity:write", True),
]


class Registry:
    def __init__(self):
        self.tools = {}

    def tool(self, **metadata):
        def decorate(fn):
            assert fn.__name__ not in self.tools
            self.tools[fn.__name__] = (fn, metadata)
            return fn

        return decorate


def bindings(registry, calls, marker):
    async def execute(tool_name, impl, /, **kwargs):
        calls.append((tool_name, impl, kwargs))
        return marker

    return dict(
        mcp=registry,
        read_only="read_only",
        write_action="write_action",
        write_idempotent="write_idempotent",
        execute_tool_async=execute,
        execute_tool_sync_async=execute,
        safe_path=lambda value: value,
        run_scan_pipeline=execute,
        truncate_response=lambda value: value,
        validate_ecosystem=lambda value: value,
        get_registry_data_raw=lambda: {},
        build_dep_graph_from_agents=lambda value: value,
    )


@pytest.mark.parametrize("name,annotation,scope,destructive", CONTRACTS)
def test_operator_dispatch_keeps_authority_and_arguments(name, annotation, scope, destructive):
    first, second = Registry(), Registry()
    calls, other_calls = [], []
    register_operator_tools(**bindings(first, calls, "first"))
    register_operator_tools(**bindings(second, other_calls, "second"))
    assert list(first.tools) == [row[0] for row in CONTRACTS]
    fn, metadata = first.tools[name]
    assert metadata["annotations"] == annotation
    signature = inspect.signature(fn)
    supplied = {
        key: parameter.default if parameter.default is not inspect.Parameter.empty else "fixture"
        for key, parameter in signature.parameters.items()
    }
    if "tenant_id" in supplied:
        supplied["tenant_id"] = "tenant-characterization"
    if "operator_scopes" in supplied:
        supplied["operator_scopes"] = "read,scope:fixture"
    assert asyncio.run(fn(**supplied)) == "first"
    assert not other_calls
    assert len(calls) == 1
    tool_name, impl, kwargs = calls[0]
    assert tool_name == name
    assert callable(impl)
    assert kwargs.get("required_scope") == scope
    assert kwargs.get("destructive", False) is destructive
    if name != "graph_export":
        for key, value in supplied.items():
            assert kwargs[key] == value


def test_graph_export_delegates_scan_and_preserves_truncation():
    registry, calls = Registry(), []
    args = bindings(registry, calls, "unused")

    async def scan(**kwargs):
        calls.append(kwargs)
        return "scan-error-envelope"

    async def execute(name, impl, **kwargs):
        assert name == "graph_export"
        return await impl()

    args.update(run_scan_pipeline=scan, execute_tool_async=execute, truncate_response=lambda value: "truncated:" + value)
    register_operator_tools(**args)
    fn = registry.tools["graph_export"][0]
    assert asyncio.run(fn(config_path="fixture-root")) == "truncated:scan-error-envelope"
    assert calls == [{"config_path": "fixture-root"}]
