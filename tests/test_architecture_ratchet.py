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


def test_raw_env_reads_are_counted_per_file_and_only_settings_owners_are_exempt(tmp_path):
    body = (
        "import os\nimport os as _os\nfrom os import environ, getenv\nfrom os import environ as env\n"
        "a = os.environ.get('A')\nb = os.getenv('B')\nc = os.environ['C']\nd = _os.environ.get('D')\n"
        "e = environ.get('E')\nf = getenv('F')\ng = env['G']\n"
        "os.environ['H'] = '1'\nos.environ.setdefault('I', '1')\nh = 'J' in os.environ\n"
    )
    metrics = _layer_metrics(tmp_path, {"cli/x.py": body, "config.py": body, "core/settings.py": body, "clean.py": "x = 1\n"})
    assert metrics["cli/x.py"]["raw_env_reads"] == 7
    assert "raw_env_reads" not in metrics["config.py"]
    assert "raw_env_reads" not in metrics["core/settings.py"]
    assert "raw_env_reads" not in metrics["clean.py"]
    assert regressions({"new.py": {"raw_env_reads": 1}}, {})
    assert regressions({"old.py": {"raw_env_reads": 3}}, {"old.py": {"raw_env_reads": 2}})
    assert not regressions({"old.py": {"raw_env_reads": 1}}, {"old.py": {"raw_env_reads": 2}})
    assert debt({"old.py": {"raw_env_reads": 2}}) == {"old.py": {"raw_env_reads": 2}}


def test_raw_env_reads_bootstrap_once_then_only_shrink():
    previous = {"old.py": {"raw_env_reads": 4}}
    assert not baseline_growth({"old.py": {"raw_env_reads": 9}}, {}, ratcheted_metrics={"file_lines"})
    assert baseline_growth({"old.py": {"raw_env_reads": 5}}, previous, ratcheted_metrics={"raw_env_reads"})
    assert baseline_growth({"new.py": {"raw_env_reads": 1}}, previous, ratcheted_metrics={"raw_env_reads"})
    assert not baseline_growth({"old.py": {"raw_env_reads": 3}}, previous, ratcheted_metrics={"raw_env_reads"})


def test_broad_except_counts_every_broad_handler_but_not_specific_ones(tmp_path):
    source = (
        "def f():\n"
        "    try:\n        pass\n    except Exception:\n        pass\n"
        "    try:\n        pass\n    except BaseException:\n        raise\n"
        "    try:\n        pass\n    except:\n        pass\n"
        "    try:\n        pass\n    except (ValueError, Exception) as exc:\n        raise RuntimeError() from exc\n"
        "    try:\n        pass\n    except (ValueError, KeyError):\n        pass\n"
        "    try:\n        pass\n    except httpx.HTTPError:\n        pass\n"
    )
    metrics = _layer_metrics(tmp_path, {"handlers.py": source, "clean.py": "try:\n    pass\nexcept OSError:\n    pass\n"})
    assert metrics["handlers.py"]["broad_except"] == 4
    assert "broad_except" not in metrics["clean.py"]


def test_broad_except_budget_only_shrinks_but_splits_can_move_handlers():
    baseline = {"old.py": {"broad_except": 3}}
    assert not regressions({"old.py": {"broad_except": 2}}, baseline)
    assert not regressions({"old.py": {"broad_except": 1}, "old_part.py": {"broad_except": 2}}, baseline)
    assert regressions({"old.py": {"broad_except": 4}}, baseline) == ["broad_except: total 4 exceeds budget 3"]
    assert regressions({"old.py": {"broad_except": 3}, "new.py": {"broad_except": 1}}, baseline)
    assert regressions({"new.py": {"broad_except": 1}}, {}) == ["broad_except: total 1 exceeds budget 0"]
    assert debt({"old.py": {"broad_except": 2}}) == {"old.py": {"broad_except": 2}}


def test_reviewed_broad_except_marker_needs_a_reason_and_is_capped(tmp_path):
    handler = "try:\n    pass\nexcept Exception:  # broad-except: {reason}\n    pass\n"
    reasoned = handler.format(reason="plugin boundary isolates third-party hooks")
    metrics = _layer_metrics(tmp_path, {"one.py": reasoned, "lazy.py": handler.format(reason="x")})
    assert "broad_except" not in metrics["one.py"]
    assert metrics["lazy.py"]["broad_except"] == 1
    capped = tmp_path / "capped"
    (capped / "src" / "agent_bom").mkdir(parents=True)
    (capped / "src" / "agent_bom" / "many.py").write_text(reasoned * 4)
    _metrics, errors = measure(capped)
    assert errors == ["many.py: 4 '# broad-except:' handlers exceed 3; catch specific errors"]
