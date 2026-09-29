"""Architecture debt cannot grow or move into a newly oversized function."""

import ast
from pathlib import Path

from scripts.check_architecture import baseline_growth, boundary_errors, debt, function_spans, measure, regressions, restrict_metrics


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
    for module in (
        "package_projection",
        "runtime_projection",
        "projection_support",
        "agent_projection",
        "credential_projection",
        "blast_projection",
        "benchmark_projection",
        "finding_projection",
        "training_projection",
        "resource_aliases",
        "build_indexes",
        "build_input",
        "build_analysis",
    ):
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


def test_api_cannot_import_cli():
    for source in (
        "from agent_bom.cli._common import _build_agents_from_inventory",
        "import agent_bom.cli",
        "from agent_bom import cli",
        "def f():\n from agent_bom.cli import main",
    ):
        assert boundary_errors("api/pipeline.py", ast.parse(source))
    assert boundary_errors("api/routes/discovery.py", ast.parse("from ...cli import _common"))
    assert not boundary_errors("api/pipeline.py", ast.parse("from agent_bom.inventory import build_agents_from_inventory"))
    assert not boundary_errors("cli/_inventory.py", ast.parse("from agent_bom.cli._common import _make_console"))


def _layer_metrics(tmp_path, files):
    root = tmp_path / "src" / "agent_bom"
    for relative, body in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    metrics, errors = measure(tmp_path)
    assert not errors
    return metrics


def test_deferred_imports_are_counted_per_file_excluding_optional_extras(tmp_path):
    metrics = _layer_metrics(
        tmp_path,
        {
            "lazy.py": (
                "import json\n"
                "def f():\n import os\n from agent_bom import models\n from . import other\n"
                "class C:\n async def g(self):\n  import boto3\n  from azure.identity import DefaultAzureCredential\n"
            ),
            "eager.py": "import os\nif os:\n import json\nclass C:\n import re\n",
        },
    )
    assert metrics["lazy.py"]["deferred_imports"] == 3
    assert "deferred_imports" not in metrics["eager.py"]
    assert regressions(metrics, {})
    assert not regressions(metrics, {"lazy.py": {"deferred_imports": 3}})
    assert regressions(metrics, {"lazy.py": {"deferred_imports": 2}})
    assert debt(metrics)["lazy.py"] == {"deferred_imports": 3}


def test_outer_layer_api_imports_are_ratcheted_separately_for_graph(tmp_path):
    metrics = _layer_metrics(
        tmp_path,
        {
            "graph/overlay.py": "from agent_bom.api import stores\ndef f():\n from ..api.auth import x\n",
            "runtime/thing.py": "from agent_bom import api\nimport agent_bom.api.server\nfrom agent_bom import graph\n",
            "api/routes/x.py": "from agent_bom.api import stores\n",
            "graph/clean.py": "from agent_bom.graph.node import UnifiedNode\n",
        },
    )
    assert metrics["graph/overlay.py"]["graph_api_imports"] == 2
    assert "api_imports" not in metrics["graph/overlay.py"]
    assert metrics["runtime/thing.py"]["api_imports"] == 2
    assert "api_imports" not in metrics["api/routes/x.py"]
    assert "graph_api_imports" not in metrics["graph/clean.py"]
    baseline = {"graph/overlay.py": {"graph_api_imports": 2, "deferred_imports": 1}, "runtime/thing.py": {"api_imports": 2}}
    assert not regressions(metrics, baseline)
    assert regressions(metrics, {**baseline, "runtime/thing.py": {"api_imports": 1}})
    assert regressions(metrics, {"runtime/thing.py": {"api_imports": 2}})


def test_new_layer_categories_bootstrap_once_then_only_shrink():
    previous = {"old.py": {"file_lines": 700}}
    current = {"old.py": {"file_lines": 700, "deferred_imports": 5}, "graph/x.py": {"graph_api_imports": 1}}
    assert not baseline_growth(current, previous, ratcheted_metrics={"file_lines"})
    assert baseline_growth(current, previous, ratcheted_metrics={"file_lines", "deferred_imports", "graph_api_imports"})
    assert baseline_growth({"old.py": {"file_lines": 701}}, previous, ratcheted_metrics={"file_lines"})
    assert not baseline_growth(
        {"old.py": {"deferred_imports": 4}}, {"old.py": {"deferred_imports": 5}}, ratcheted_metrics={"deferred_imports"}
    )


def test_write_baseline_bootstraps_only_categories_the_stored_baseline_lacks():
    metrics = {"old.py": {"file_lines": 701, "deferred_imports": 5}}
    stored = {"old.py": {"file_lines": 700}}
    assert not regressions(restrict_metrics(metrics, {"complexity"}), stored)
    assert regressions(restrict_metrics(metrics, {"file_lines"}), stored)
    assert restrict_metrics(metrics, {"deferred_imports"}) == {"old.py": {"deferred_imports": 5}}


def test_repository_has_no_api_to_cli_imports():
    source = Path(__file__).resolve().parents[1] / "src" / "agent_bom"
    offenders = [
        error
        for path in sorted((source / "api").rglob("*.py"))
        for error in boundary_errors(path.relative_to(source).as_posix(), ast.parse(path.read_text()))
        if "must not import the CLI" in error
    ]
    assert offenders == []


def test_gateway_forwarding_has_one_owner_and_no_composition_import():
    assert boundary_errors("gateway_server.py", ast.parse("async def forward_authorized_request(context): pass"))
    assert boundary_errors("api/gateway_forward.py", ast.parse("from agent_bom.gateway_server import GatewaySettings"))
    assert not boundary_errors("api/gateway_forward.py", ast.parse("from agent_bom.runtime.gateway_contracts import AuditSink"))


def test_import_debt_is_budgeted_per_category_so_splits_can_move_it():
    baseline = {"big.py": {"deferred_imports": 3, "api_imports": 2}}
    split = {"big.py": {"deferred_imports": 1, "api_imports": 1}, "big_part.py": {"deferred_imports": 2, "api_imports": 1}}
    assert not regressions(split, baseline)
    grown = {"big.py": {"deferred_imports": 1}, "big_part.py": {"deferred_imports": 3}}
    assert regressions(grown, baseline) == ["deferred_imports: total 4 exceeds budget 3"]
    assert regressions({"new.py": {"graph_api_imports": 1}}, {}) == ["graph_api_imports: total 1 exceeds budget 0"]


def test_operator_registrations_cannot_import_server_composition():
    for source in (
        "from agent_bom.mcp_server import _execute_tool_async",
        "from ...mcp_server_operator_tools import register_operator_tools",
        "def f():\n import agent_bom.mcp_server",
    ):
        assert boundary_errors("mcp_tools/operator/graphs.py", ast.parse(source))
    assert not boundary_errors("mcp_tools/operator/graphs.py", ast.parse("from .bindings import OperatorToolBindings"))


def test_hard_ceiling_rejects_any_unit_over_1000_lines_not_in_the_burn_down():
    from scripts.check_architecture import HARD_CEILING, ceiling_errors

    assert HARD_CEILING == 1000
    metrics = {"big.py": {"file_lines": 1001}, "big.py::run": {"function_lines": 1200}, "ok.py": {"file_lines": 1000}}
    errors = ceiling_errors(metrics, {})
    assert any(error.startswith("big.py: file_lines 1001 exceeds hard ceiling 1000") for error in errors)
    assert any(error.startswith("big.py::run: function_lines 1200 exceeds hard ceiling 1000") for error in errors)
    assert not any(error.startswith("ok.py") for error in errors)
    assert not ceiling_errors(metrics, {"big.py": 1001, "big.py::run": 1200})


def test_hard_ceiling_is_independent_of_the_soft_baseline():
    from scripts.check_architecture import ceiling_errors

    # A soft-baseline allowance above the ceiling does not exempt a unit.
    metrics = {"big.py": {"file_lines": 1500}}
    assert not regressions(metrics, {"big.py": {"file_lines": 1500}})
    assert ceiling_errors(metrics, {})


def test_burn_down_entries_cannot_grow_and_must_be_removed_once_under_the_ceiling():
    from scripts.check_architecture import ceiling_errors

    burn_down = {"big.py": 1200, "big.py::run": 1100}
    assert ceiling_errors({"big.py": {"file_lines": 1201}, "big.py::run": {"function_lines": 1100}}, burn_down)
    assert not ceiling_errors({"big.py": {"file_lines": 1150}, "big.py::run": {"function_lines": 1050}}, burn_down)
    stale = ceiling_errors({"big.py": {"file_lines": 1150}, "big.py::run": {"function_lines": 900}}, burn_down)
    assert stale == ["big.py::run: burn-down entry is now 900 lines, at or under the hard ceiling 1000; remove it"]
    gone = ceiling_errors({"big.py": {"file_lines": 1150}}, burn_down)
    assert gone == ["big.py::run: burn-down entry no longer exists; remove it"]


def test_editing_the_baseline_cannot_add_or_raise_burn_down_entries():
    from scripts.check_architecture import burn_down_growth

    previous = {"big.py": 1200, "big.py::run": 1100}
    assert not burn_down_growth({"big.py": 1150}, previous)
    assert not burn_down_growth(previous, previous)
    assert burn_down_growth({"big.py": 1201, "big.py::run": 1100}, previous) == ["big.py: burn-down allowance 1201 exceeds trusted 1200"]
    assert burn_down_growth({**previous, "new.py": 1001}, previous) == ["new.py: burn-down entry is not in the trusted baseline"]
    # A trusted baseline without a burn-down section is the one-time rollout.
    assert not burn_down_growth({"big.py": 1200}, None)


def test_burn_down_is_seeded_from_units_over_the_ceiling_and_reported_with_counts():
    from scripts.check_architecture import burn_down_report, ceiling_burn_down

    metrics = {
        "a.py": {"file_lines": 1300, "deferred_imports": 2},
        "a.py::f": {"function_lines": 1001, "complexity": 40},
        "b.py": {"file_lines": 999},
        "b.py::g": {"function_lines": 1000},
    }
    burn_down = ceiling_burn_down(metrics)
    assert burn_down == {"a.py": 1300, "a.py::f": 1001}
    report = burn_down_report(burn_down)
    assert report[0] == "Hard 1000-line ceiling burn-down: 2 entries (1 files, 1 functions)"
    assert report[1:] == ["  function  1001  a.py::f", "  file      1300  a.py"]


def test_ceiling_check_seeds_once_then_holds_against_the_trusted_base():
    from scripts.check_architecture import ceiling_check

    metrics = {"big.py": {"file_lines": 1100}, "fixed.py": {"file_lines": 400}}
    # No stored burn-down: a plain check has no exemptions, writing seeds it.
    assert ceiling_check(metrics, {}, None, writing=False)
    assert not ceiling_check(metrics, {}, None, writing=True)
    stored = {"ceiling_burn_down": {"big.py": 1100, "fixed.py": 1200}}
    # A plain check demands the stale entry's removal; writing removes it.
    assert ceiling_check(metrics, stored, None, writing=False) == [
        "fixed.py: burn-down entry is now 400 lines, at or under the hard ceiling 1000; remove it"
    ]
    assert not ceiling_check(metrics, stored, None, writing=True)
    # A new oversized unit blocks writing too, so the baseline cannot absorb it.
    assert ceiling_check({**metrics, "new.py": {"file_lines": 1001}}, stored, None, writing=True)
    trusted = {"ceiling_burn_down": {"big.py": 1050}}
    assert ceiling_check(metrics, {"ceiling_burn_down": {"big.py": 1100}}, trusted, writing=False) == [
        "big.py: burn-down allowance 1100 exceeds trusted 1050"
    ]


def test_repository_burn_down_matches_the_measured_tree():
    import json

    from scripts.check_architecture import BASELINE, ceiling_burn_down

    root = Path(__file__).resolve().parents[1]
    stored = json.loads((root / BASELINE).read_text())
    metrics, _ = measure(root)
    assert stored["ceiling_burn_down"] == ceiling_burn_down(metrics)
