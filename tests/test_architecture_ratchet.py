"""Architecture debt cannot grow or move into a newly oversized function."""

import ast

from scripts.check_architecture import baseline_growth, boundary_errors, debt, function_spans, measure, regressions


def test_new_and_growing_debt_fails_but_reductions_pass():
    baseline = {"old.py::big": {"function_lines": 100}}
    assert regressions({"old.py::big": {"function_lines": 101}}, baseline)
    assert regressions({"new.py::big": {"function_lines": 81}}, baseline)
    assert not regressions({"old.py::big": {"function_lines": 90}}, baseline)
    reduced = debt({"old.py::big": {"function_lines": 90}})
    assert regressions({"old.py::big": {"function_lines": 91}}, reduced)


def test_nested_functions_have_distinct_qualified_names():
    tree = ast.parse("class One:\n def work(self):\n  def inner():\n   pass\nclass Two:\n def work(self):\n  pass\n")
    assert [name for name, _, _ in function_spans(tree)] == ["One.work", "One.work.inner", "Two.work"]


def test_kernel_rejects_absolute_relative_and_deferred_adapter_imports():
    for source in ("from agent_bom.api import server", "from ..api import server", "def f():\n import agent_bom.models"):
        assert boundary_errors("core/example.py", ast.parse(source))
    assert not boundary_errors("core/example.py", ast.parse("from .severity import Severity\nimport math"))


def test_semantic_owner_cannot_be_reimplemented_in_adapter():
    tree = ast.parse("def normalize_severity(value):\n return value\n")
    assert boundary_errors("api/example.py", tree)
    assert not boundary_errors("core/severity.py", tree)


def test_editing_baseline_cannot_approve_new_or_larger_exceptions():
    previous = {"old.py": {"file_lines": 700}}
    assert baseline_growth({"old.py": {"file_lines": 701}}, previous)
    assert baseline_growth({"new.py": {"file_lines": 650}}, previous)
    assert not baseline_growth({"old.py": {"file_lines": 690}}, previous)


def test_complexity_cannot_be_hidden_with_noqa(tmp_path):
    root = tmp_path / "src" / "agent_bom"
    root.mkdir(parents=True)
    body = "def hidden(value):  # noqa: C901\n" + "".join(f"    if value == {i}:\n        return {i}\n" for i in range(16))
    (root / "sample.py").write_text(body)
    metrics, errors = measure(tmp_path)
    assert not errors
    assert metrics["sample.py::hidden"]["complexity"] == 17
    assert regressions(metrics, {})


def test_graph_cannot_restore_credential_api_dependency():
    for source in (
        "from agent_bom.api.credential_expiry import classify_credential",
        "from ..api.credential_expiry import classify_credential",
        "from agent_bom.api import credential_expiry",
        "def f():\n import agent_bom.api.credential_expiry",
    ):
        assert boundary_errors("graph/nhi_governance.py", ast.parse(source))
    assert not boundary_errors("graph/nhi_governance.py", ast.parse("from agent_bom.identity.credential_policy import classify_credential"))


def test_credential_decisions_have_one_domain_owner():
    for function in ("classify_credential_record", "credential_governance_summary"):
        tree = ast.parse(f"def {function}(value):\n return value\n")
        assert boundary_errors("api/credential_expiry.py", tree)
        assert not boundary_errors("core/credential_policy.py", tree)


def test_graph_persistence_service_cannot_import_its_callers_or_store_singleton():
    for source in (
        "from agent_bom.api.pipeline import _get_graph_store",
        "from .pipeline import _get_graph_store",
        "from agent_bom.api import pipeline",
        "def f():\n from agent_bom.api.stores import _get_graph_store",
        "import agent_bom.api.server",
    ):
        assert boundary_errors("api/graph_persistence.py", ast.parse(source))
    assert not boundary_errors("api/graph_persistence.py", ast.parse("from agent_bom.api.graph_store import GraphStoreProtocol"))


def test_explicit_tenant_validation_has_one_domain_owner():
    tree = ast.parse("def require_explicit_tenant_id(value):\n return value\n")
    assert boundary_errors("api/tenancy.py", tree)
    assert not boundary_errors("core/tenancy.py", tree)


def test_dispatch_cannot_restore_unchecked_tenant_binding():
    from scripts.check_architecture import TENANT_DISPATCH_ADAPTERS

    for path in TENANT_DISPATCH_ADAPTERS:
        assert boundary_errors(path, ast.parse("from agent_bom.api.postgres_common import set_current_tenant"))
        assert not boundary_errors(path, ast.parse("from agent_bom.api.tenant_worker import tenant_bound_context"))
    definition = ast.parse("def tenant_bound_context(tenant): pass")
    assert boundary_errors("api/scheduler.py", definition)
    assert not boundary_errors("api/tenant_worker.py", definition)


def test_gateway_relay_cannot_import_http_app_or_api_adapters():
    for source in (
        "import agent_bom.gateway_server",
        "from agent_bom import gateway_server",
        "from agent_bom.api.auth import get_key_store",
        "from ..api import auth",
        "from .. import gateway_server",
    ):
        assert boundary_errors("runtime/gateway_relay.py", ast.parse(source))
    assert not boundary_errors("runtime/gateway_relay.py", ast.parse("from .gateway_relay_contract import RelayForwardRequest"))


def test_gateway_services_cannot_import_composition_root():
    for path in ("gateway_settings", "gateway_audit", "gateway_audit_registry", "gateway_audit_local", "gateway_contracts"):
        for source in ("from agent_bom import gateway_server", "from ..gateway_server import GatewaySettings"):
            assert boundary_errors(f"runtime/{path}.py", ast.parse(source))


def test_gateway_audit_factories_have_single_owners():
    for function, owner in (("build_control_plane_audit_sink", "gateway_audit"), ("build_local_gateway_audit_sink", "gateway_audit_local")):
        tree = ast.parse(f"def {function}():\n pass")
        assert boundary_errors("gateway_server.py", tree)
        assert not boundary_errors(f"runtime/{owner}.py", tree)


def test_gateway_http_helpers_cannot_depend_on_composition_root():
    for module in ("gateway_auth", "gateway_request", "gateway_rate_limit", "gateway_context"):
        assert boundary_errors(f"api/{module}.py", ast.parse("from agent_bom import gateway_server"))
    for function, owner in (
        ("_authenticate_gateway_request", "gateway_auth"),
        ("_request_groups", "gateway_request"),
        ("_build_gateway_rate_limit_store", "gateway_rate_limit"),
    ):
        tree = ast.parse(f"def {function}(): pass")
        assert boundary_errors("gateway_server.py", tree)
        assert not boundary_errors(f"api/{owner}.py", tree)


def test_report_projections_cannot_depend_on_orchestration_or_api():
    for module in ("package_projection", "runtime_projection", "projection_support"):
        for source in ("from .builder import build_unified_graph_from_report", "from agent_bom.api import stores"):
            assert boundary_errors(f"graph/{module}.py", ast.parse(source))
        assert not boundary_errors(f"graph/{module}.py", ast.parse("from agent_bom.graph.node import UnifiedNode"))


def test_report_projection_judgments_cannot_be_duplicated_in_builder():
    for name, owner in (("_package_evidence", "package_projection"), ("_add_agentic_identity_graph_projections", "runtime_projection")):
        tree = ast.parse(f"def {name}():\n pass")
        assert boundary_errors("graph/builder.py", tree)
        assert not boundary_errors(f"graph/{owner}.py", tree)


def test_graph_ports_and_services_cannot_import_concrete_storage():
    for path in ("graph/ports.py", "graph/correlation_service.py"):
        for source in (
            "from agent_bom.api.graph_store import SQLiteGraphStore",
            "from ..api import graph_store",
            "import agent_bom.db.graph_store",
        ):
            assert boundary_errors(path, ast.parse(source))
        assert not boundary_errors(path, ast.parse("from agent_bom.graph.ports import GraphStoreProtocol"))
    contract = ast.parse("class GraphStoreProtocol: pass")
    assert boundary_errors("api/graph_store.py", contract)
    assert not boundary_errors("graph/ports.py", contract)


def test_shared_semantic_aliases_cannot_restore_duplicate_implementations():
    for path, name in (
        ("transitive.py", "_go_encode_module"),
        ("version_utils.py", "_go_encode_module"),
        ("compliance_nist_catalog.py", "evaluated_control_status"),
        ("output/compliance_narrative.py", "_control_status"),
        ("core/credential_policy.py", "_parse_timestamp"),
        ("graph/nhi_governance.py", "_parse_timestamp"),
    ):
        assert boundary_errors(path, ast.parse(f"def {name}(): pass"))


def test_risk_conditions_cannot_import_orchestration_or_adapters():
    for source in ("from agent_bom import proxy_policy", "from agent_bom.api import auth"):
        assert boundary_errors("runtime/risk_conditions.py", ast.parse(source))


def test_gateway_policy_reload_cannot_import_adapters():
    for source in ("from agent_bom.api import gateway_policy", "import agent_bom.gateway_server"):
        assert boundary_errors("runtime/gateway_policy_reload.py", ast.parse(source))
    assert not boundary_errors("runtime/gateway_policy_reload.py", ast.parse("from agent_bom.security import sanitize_error"))
