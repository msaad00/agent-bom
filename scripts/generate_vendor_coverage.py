#!/usr/bin/env python3
"""Generate or verify the vendor-coverage matrix (docs/VENDOR_COVERAGE.{md,json}).

Standard library only: every value is read from source by ``ast`` parsing of
literal constants, from checked-in JSON, or from file globs. The script never
imports ``agent_bom``, so it runs without the package's third-party
dependencies. Output is deterministic (sorted keys, no timestamps).

Usage:
    python scripts/generate_vendor_coverage.py --write
    python scripts/generate_vendor_coverage.py --check
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import sys
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PKG = "src/agent_bom"
DOC_MD = ROOT / "docs" / "VENDOR_COVERAGE.md"
DOC_JSON = ROOT / "docs" / "VENDOR_COVERAGE.json"
SCRIPT = "scripts/generate_vendor_coverage.py"

GAP = "—"
YES = "✓"

Source = dict[str, str]


# ── AST helpers ──────────────────────────────────────────────────────────────


@cache
def _module(path: str) -> ast.Module:
    return ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)


def _src(path: str, symbol: str, method: str = "ast") -> Source:
    return {"path": path, "symbol": symbol, "method": method}


def _assignment(path: str, name: str) -> ast.expr:
    for node in _module(path).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return node.value
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name and node.value is not None:
            return node.value
    raise SystemExit(f"{path}: module-level constant {name} not found")


def _literal(node: ast.expr, path: str) -> Any:
    """Evaluate a literal expression, resolving module-level names in ``path``."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [_literal(elt, path) for elt in node.elts]
    if isinstance(node, ast.Name):
        return _literal(_assignment(path, node.id), path)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"frozenset", "set", "tuple", "list"}:
        return _literal(node.args[0], path) if node.args else []
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _literal(node.left, path) + _literal(node.right, path)
    raise SystemExit(f"{path}: cannot statically evaluate {ast.unparse(node)}")


def _strings(path: str, name: str) -> list[str]:
    return sorted({str(v) for v in _literal(_assignment(path, name), path)})


def _dict_keys(path: str, name: str) -> list[str]:
    node = _assignment(path, name)
    if not isinstance(node, ast.Dict):
        raise SystemExit(f"{path}: {name} is not a dict literal")
    return sorted(str(_literal(k, path)) for k in node.keys if k is not None)


def _enum_values(path: str, class_name: str) -> list[str]:
    for node in _module(path).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return [
                stmt.value.value
                for stmt in node.body
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)
            ]
    raise SystemExit(f"{path}: class {class_name} not found")


def _class_fields(path: str, class_name: str) -> list[str]:
    for node in _module(path).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return [s.target.id for s in node.body if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)]
    raise SystemExit(f"{path}: class {class_name} not found")


def _call_kwargs(call: ast.Call, path: str, positional: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, arg in zip(positional or [], call.args):
        out[name] = _literal(arg, path)
    for kw in call.keywords:
        if kw.arg is None:
            continue
        try:
            out[kw.arg] = _literal(kw.value, path)
        except SystemExit:
            out[kw.arg] = None
    return out


def _calls(tree: ast.AST, func_name: str) -> Iterable[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == func_name:
            yield node


def _function(path: str, name: str) -> ast.FunctionDef:
    for node in ast.walk(_module(path)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise SystemExit(f"{path}: function {name} not found")


def _glob(pattern: str) -> list[str]:
    return sorted(p.relative_to(ROOT).as_posix() for p in ROOT.glob(pattern) if p.is_file())


# ── Matrix A: cloud and AI-infrastructure vendors ───────────────────────────

_DSPM_STORE_PROVIDER = {"s3": "aws", "gcs": "gcp", "azure_blob": "azure", "db": "database"}

_P_ENTRY = f"{PKG}/cli/_entry_points.py"
_P_CONN = f"{PKG}/api/connection_store.py"
_P_SCHED = f"{PKG}/api/connection_scheduler.py"
_P_CLOUD = f"{PKG}/cloud/__init__.py"
_P_ROUTES = f"{PKG}/api/routes/cloud.py"
_P_BENCH_JSON = f"{PKG}/cloud/benchmark_inventory.json"
_P_BENCH_PROV = f"{PKG}/cloud/benchmark_provenance.py"
_P_AUTHZ = f"{PKG}/cloud/authorization_evidence.py"
_P_AWS_IAM = f"{PKG}/cloud/aws_iam_evaluator.py"
_P_SIDESCAN = f"{PKG}/cloud/side_scan_lifecycle_status.py"
_P_RUNTIME = f"{PKG}/cloud/runtime_workload_evidence.py"
_P_SCOPES = f"{PKG}/api/cloud_scan_scopes.py"


def _benchmark_provenance() -> dict[str, dict[str, Any]]:
    node = _assignment(_P_BENCH_PROV, "BENCHMARK_PROVENANCE")
    if not isinstance(node, ast.Dict):
        raise SystemExit(f"{_P_BENCH_PROV}: BENCHMARK_PROVENANCE is not a dict literal")
    out: dict[str, dict[str, Any]] = {}
    for key, value in zip(node.keys, node.values):
        if key is None or not isinstance(value, ast.Call):
            continue
        out[str(_literal(key, _P_BENCH_PROV))] = _call_kwargs(value, _P_BENCH_PROV)
    return out


def _kubernetes_provenance() -> dict[str, Any]:
    node = _assignment(_P_BENCH_PROV, "KUBERNETES_BENCHMARK_PROVENANCE")
    if not isinstance(node, ast.Call):
        raise SystemExit(f"{_P_BENCH_PROV}: KUBERNETES_BENCHMARK_PROVENANCE is not a call")
    return _call_kwargs(node, _P_BENCH_PROV)


def _side_scan_capabilities() -> dict[str, dict[str, Any]]:
    fields = _class_fields(_P_SIDESCAN, "SideScanProviderCapability")
    factory = _function(_P_SIDESCAN, "side_scan_provider_capabilities")
    out: dict[str, dict[str, Any]] = {}
    for call in _calls(factory, "SideScanProviderCapability"):
        record = _call_kwargs(call, _P_SIDESCAN, fields)
        out[str(record["provider"])] = record
    return out


def _cell(value: Any, display: str, source: Source) -> dict[str, Any]:
    return {"display": display, "source": source, "value": value}


def _membership_lane(lane_id: str, title: str, members: list[str], source: Source) -> dict[str, Any]:
    return {"id": lane_id, "title": title, "members": members, "source": source}


def build_cloud_matrix() -> dict[str, Any]:
    connect_src = _src(_P_ENTRY, "_CONNECT_SOURCES")
    api_src = _src(_P_CONN, "SUPPORTED_PROVIDERS")
    sched_src = _src(_P_SCHED, "_SCHEDULABLE_PROVIDERS")
    disc_src = _src(_P_CLOUD, "_PROVIDERS")
    inv_src = _src(_P_ROUTES, "_INVENTORY_PROVIDERS")
    runtime_src = _src(_P_RUNTIME, "_VALID_PROVIDERS")

    membership = [
        _membership_lane("connect", "Connect (CLI)", _dict_keys(_P_ENTRY, "_CONNECT_SOURCES"), connect_src),
        _membership_lane("api_connection", "API connection", _strings(_P_CONN, "SUPPORTED_PROVIDERS"), api_src),
        _membership_lane("scheduled", "Scheduled scans", _strings(_P_SCHED, "_SCHEDULABLE_PROVIDERS"), sched_src),
        _membership_lane("ai_discovery", "AI/agent discovery", _dict_keys(_P_CLOUD, "_PROVIDERS"), disc_src),
        _membership_lane("deep_inventory", "Deep inventory", _strings(_P_ROUTES, "_INVENTORY_PROVIDERS"), inv_src),
    ]

    # CIS / benchmark posture.
    inventory = json.loads((ROOT / _P_BENCH_JSON).read_text(encoding="utf-8"))["providers"]
    provenance = _benchmark_provenance()
    k8s = _kubernetes_provenance()

    # Identity / CIEM.
    authz = _enum_values(_P_AUTHZ, "AuthorizationProvider")
    aws_iam = (ROOT / _P_AWS_IAM).is_file()

    # Data / DSPM.
    dspm: dict[str, list[str]] = {}
    for path in _glob(f"{PKG}/cloud/*_data_classifier.py"):
        store = Path(path).name.removesuffix("_data_classifier.py")
        dspm.setdefault(_DSPM_STORE_PROVIDER.get(store, store), []).append(path)

    # Side-scan.
    side_scan = _side_scan_capabilities()

    # Change-event ingest.
    events: dict[str, str] = {}
    for path in _glob(f"{PKG}/cloud/*event_ingest.py"):
        name = Path(path).name
        provider = "aws" if name == "event_ingest.py" else name.removesuffix("_event_ingest.py")
        events[provider] = path

    runtime = _strings(_P_RUNTIME, "_VALID_PROVIDERS")

    providers: set[str] = set()
    for lane in membership:
        providers.update(lane["members"])
    providers.update(inventory)
    providers.update(provenance)
    providers.add(str(k8s["provider"]))
    providers.update(authz)
    if aws_iam:
        providers.add("aws")
    providers.update(dspm)
    providers.update(side_scan)
    providers.update(events)
    providers.update(runtime)

    lanes = [{"id": lane["id"], "title": lane["title"], "source": lane["source"]} for lane in membership] + [
        {"id": "cis_posture", "title": "Benchmark posture", "source": _src(_P_BENCH_JSON, "providers", "json")},
        {"id": "identity_ciem", "title": "Identity/CIEM", "source": _src(_P_AUTHZ, "AuthorizationProvider")},
        {"id": "data_dspm", "title": "Data/DSPM", "source": _src(f"{PKG}/cloud/*_data_classifier.py", "module files", "glob")},
        {"id": "side_scan", "title": "Side-scan", "source": _src(_P_SIDESCAN, "side_scan_provider_capabilities")},
        {"id": "change_events", "title": "Change-event ingest", "source": _src(f"{PKG}/cloud/*event_ingest.py", "module files", "glob")},
        {"id": "runtime_workload", "title": "Runtime workload evidence", "source": runtime_src},
    ]

    rows: list[dict[str, Any]] = []
    gap_count = 0
    for provider in sorted(providers):
        cells: dict[str, dict[str, Any]] = {}
        for lane in membership:
            present = provider in lane["members"]
            cells[lane["id"]] = _cell(present, YES if present else GAP, lane["source"])

        if provider in inventory:
            entry = inventory[provider]
            prov = provenance.get(provider, {})
            implemented = entry["implemented_control_count"]
            official = entry["official_control_count"]
            cells["cis_posture"] = _cell(
                {
                    "benchmark_name": prov.get("benchmark_name"),
                    "benchmark_version": prov.get("benchmark_version"),
                    "implemented_control_count": implemented,
                    "official_control_count": official,
                },
                f"{implemented}/{official if official is not None else 'n/a'}",
                {
                    "path": f"{_P_BENCH_JSON}; {_P_BENCH_PROV}",
                    "symbol": f"providers.{provider}; BENCHMARK_PROVENANCE[{provider!r}]",
                    "method": "json+ast",
                },
            )
        elif provider == k8s["provider"]:
            cells["cis_posture"] = _cell(
                {
                    "benchmark_name": k8s.get("benchmark_name"),
                    "benchmark_version": k8s.get("benchmark_version"),
                    "implemented_control_count": None,
                    "official_control_count": k8s.get("official_control_count"),
                },
                "provenance; count n/a",
                _src(_P_BENCH_PROV, "KUBERNETES_BENCHMARK_PROVENANCE"),
            )
        else:
            cells["cis_posture"] = _cell(None, GAP, _src(_P_BENCH_JSON, "providers", "json"))

        if provider in authz:
            cells["identity_ciem"] = _cell("authorization_evidence", YES, _src(_P_AUTHZ, "AuthorizationProvider"))
        elif provider == "aws" and aws_iam:
            cells["identity_ciem"] = _cell("module", f"{YES} (module)", _src(_P_AWS_IAM, "module file", "file-exists"))
        else:
            cells["identity_ciem"] = _cell(None, GAP, _src(_P_AUTHZ, "AuthorizationProvider"))

        if provider in dspm:
            stores = [Path(p).name.removesuffix("_data_classifier.py") for p in dspm[provider]]
            cells["data_dspm"] = _cell(stores, ", ".join(stores), _src("; ".join(dspm[provider]), "module file", "glob"))
        else:
            cells["data_dspm"] = _cell(None, GAP, _src(f"{PKG}/cloud/*_data_classifier.py", "module files", "glob"))

        if provider in side_scan:
            cap = side_scan[provider]
            smoke = "smoke" if cap.get("credentialed_smoke") else "no live smoke"
            cells["side_scan"] = _cell(
                {"credentialed_smoke": cap.get("credentialed_smoke"), "executor": cap.get("executor")},
                f"{cap.get('executor')} ({smoke})",
                _src(_P_SIDESCAN, "side_scan_provider_capabilities"),
            )
        else:
            cells["side_scan"] = _cell(None, GAP, _src(_P_SIDESCAN, "side_scan_provider_capabilities"))

        if provider in events:
            cells["change_events"] = _cell(True, YES, _src(events[provider], "module file", "glob"))
        else:
            cells["change_events"] = _cell(False, GAP, _src(f"{PKG}/cloud/*event_ingest.py", "module files", "glob"))

        present = provider in runtime
        cells["runtime_workload"] = _cell(present, YES if present else GAP, runtime_src)

        gap_count += sum(1 for c in cells.values() if c["display"] == GAP)
        rows.append({"cells": cells, "provider": provider})

    return {"gap_count": gap_count, "lanes": lanes, "rows": rows}


# ── Matrix B: integrations by category ──────────────────────────────────────


def _importers() -> list[dict[str, Any]]:
    out = []
    for path in _glob(f"{PKG}/parsers/importers/*.py"):
        for call in _calls(_module(path), "ImporterManifest"):
            kw = _call_kwargs(call, path)
            out.append({"formats": kw.get("formats"), "name": kw.get("name"), "path": path, "tool": kw.get("tool")})
    return sorted(out, key=lambda item: str(item["name"]))


def _siem_connectors() -> list[str]:
    path = f"{PKG}/siem/__init__.py"
    names = set(_dict_keys(path, "_CONNECTORS"))
    func = _function(path, "list_connectors")
    names.update(n.value for n in ast.walk(func) if isinstance(n, ast.Constant) and isinstance(n.value, str))
    return sorted(names)


def _endpoint_providers() -> list[str]:
    path = f"{PKG}/connectors/endpoints/models.py"
    for node in _module(path).body:
        if isinstance(node, ast.ClassDef) and node.name == "ConnectionSpec":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == "provider":
                    ann = stmt.annotation
                    if isinstance(ann, ast.Subscript):
                        return sorted(str(v) for v in _literal(ann.slice, path))
    raise SystemExit(f"{path}: ConnectionSpec.provider Literal not found")


def _identity_providers() -> list[str]:
    path = f"{PKG}/cli/_identity_group.py"
    func = _function(path, "discover_cmd")
    for deco in func.decorator_list:
        if not isinstance(deco, ast.Call) or not any(isinstance(a, ast.Constant) and a.value == "--provider" for a in deco.args):
            continue
        for kw in deco.keywords:
            if kw.arg == "type" and isinstance(kw.value, ast.Call) and kw.value.args:
                return sorted(v for v in _literal(kw.value.args[0], path) if v != "all")
    raise SystemExit(f"{path}: discover --provider click.Choice not found")


_RULE_ID = re.compile(r"^([A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*)-(\d+)$")


def _iac_rule_families() -> dict[str, int]:
    ids: set[str] = set()
    for path in _glob(f"{PKG}/iac/**/*.py"):
        for node in ast.walk(_module(path)):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "rule_id" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        ids.add(kw.value.value)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "rule_id"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        ids.add(value.value)
    families: dict[str, int] = {}
    for rule_id in ids:
        match = _RULE_ID.match(rule_id)
        if match:
            families[match.group(1)] = families.get(match.group(1), 0) + 1
    return dict(sorted(families.items()))


def _agent_clients() -> dict[str, Any]:
    models = f"{PKG}/models.py"
    disc = f"{PKG}/discovery/__init__.py"
    members: dict[str, str] = {}
    for node in _module(models).body:
        if isinstance(node, ast.ClassDef) and node.name == "AgentType":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name) and isinstance(stmt.value, ast.Constant):
                    members[stmt.targets[0].id] = str(stmt.value.value)
    members.pop("CUSTOM", None)
    locations = _assignment(disc, "CONFIG_LOCATIONS")
    with_paths: set[str] = set()
    if isinstance(locations, ast.Dict):
        for key, value in zip(locations.keys, locations.values):
            if not (isinstance(key, ast.Attribute) and isinstance(value, ast.Dict)):
                continue
            for platform, paths in zip(value.keys, value.values):
                if (
                    isinstance(platform, ast.Constant)
                    and platform.value in {"Darwin", "Linux", "Windows"}
                    and isinstance(paths, ast.List)
                    and paths.elts
                ):
                    with_paths.add(key.attr)
    levels: dict[str, list[str]] = {"config_paths": [], "dynamic_or_workspace": []}
    for attr, value in members.items():
        levels["config_paths" if attr in with_paths else "dynamic_or_workspace"].append(value)
    return {level: sorted(values) for level, values in levels.items()}


def build_integrations() -> list[dict[str, Any]]:
    categories: list[dict[str, Any]] = []

    def add(cat_id: str, title: str, items: list[Any], sources: list[Source], note: str = "") -> None:
        categories.append({"id": cat_id, "items": items, "note": note, "sources": sources, "title": title})

    importers = _importers()
    add(
        "third_party_importers",
        "Third-party report importers",
        [{"formats": i["formats"], "name": i["name"], "tool": i["tool"]} for i in importers],
        [_src(i["path"], "ImporterManifest(...)") for i in importers],
    )
    ext = f"{PKG}/parsers/external_scanners.py"
    add("builtin_report_formats", "Built-in report formats", _strings(ext, "BUILTIN_REPORT_FORMATS"), [_src(ext, "BUILTIN_REPORT_FORMATS")])
    tick = f"{PKG}/ticketing/models.py"
    add("ticketing", "Ticketing providers", _strings(tick, "SUPPORTED_TICKETING_PROVIDERS"), [_src(tick, "SUPPORTED_TICKETING_PROVIDERS")])
    conn = f"{PKG}/connectors/__init__.py"
    add("saas_connectors", "SaaS connectors", _dict_keys(conn, "_CONNECTORS"), [_src(conn, "_CONNECTORS")])
    siem = f"{PKG}/siem/__init__.py"
    add("siem", "SIEM connectors", _siem_connectors(), [_src(siem, "_CONNECTORS"), _src(siem, "list_connectors")])
    exp = f"{PKG}/export/destinations.py"
    deferred = _strings(exp, "DEFERRED_EXPORT_KINDS")
    add(
        "export_destinations",
        "Export destinations",
        _strings(exp, "SUPPORTED_EXPORT_KINDS") + [f"{d} (deferred)" for d in deferred],
        [_src(exp, "SUPPORTED_EXPORT_KINDS"), _src(exp, "DEFERRED_EXPORT_KINDS")],
        "" if deferred else "DEFERRED_EXPORT_KINDS is empty.",
    )
    ep = f"{PKG}/connectors/endpoints/models.py"
    add("endpoint_inventory", "Endpoint inventory (EDR/MDM)", _endpoint_providers(), [_src(ep, "ConnectionSpec.provider")])
    dp = f"{PKG}/device_posture.py"
    add("device_posture", "Device posture connectors", _dict_keys(dp, "_CONNECTORS"), [_src(dp, "_CONNECTORS")])
    ident = f"{PKG}/cli/_identity_group.py"
    add(
        "identity_nhi",
        "Identity / NHI discovery",
        _identity_providers(),
        [_src(ident, "discover_cmd --provider click.Choice")],
        "The `all` choice is excluded.",
    )
    adv = f"{PKG}/advisory_sources.py"
    add(
        "advisory_sources",
        "Advisory sources",
        [f"{s} (primary)" for s in _literal(_assignment(adv, "PRIMARY_ADVISORY_SOURCES"), adv)]
        + [f"{s} (enrichment)" for s in _literal(_assignment(adv, "ENRICHMENT_ADVISORY_SOURCES"), adv)],
        [_src(adv, "PRIMARY_ADVISORY_SOURCES"), _src(adv, "ENRICHMENT_ADVISORY_SOURCES")],
    )
    families = _iac_rule_families()
    add(
        "iac_rule_families",
        "IaC rule families",
        [{"family": k, "rule_count": v} for k, v in families.items()],
        [_src(f"{PKG}/iac/**/*.py", 'rule_id="PREFIX-NNN" / "rule_id": "PREFIX-NNN" literals', "ast-scan")],
        "Distinct rule-id literals per prefix.",
    )
    clients = _agent_clients()
    add(
        "agent_clients",
        "Agent / MCP clients",
        [{"agent_type": c, "support_level": level} for level, values in clients.items() for c in values],
        [
            _src(f"{PKG}/models.py", "AgentType"),
            _src(f"{PKG}/discovery/__init__.py", "CONFIG_LOCATIONS"),
            _src(f"{PKG}/discovery/coverage.py", "supported_clients", "logic-mirrored"),
        ],
        "support_level follows discovery/coverage.py: config_paths when CONFIG_LOCATIONS lists a path for any platform; "
        "AgentType.CUSTOM is excluded.",
    )
    return categories


# ── Declared provider lists that disagree ───────────────────────────────────


def build_disagreements() -> list[dict[str, Any]]:
    bench_json = sorted(json.loads((ROOT / _P_BENCH_JSON).read_text(encoding="utf-8"))["providers"])
    lists = {
        "connect": (_dict_keys(_P_ENTRY, "_CONNECT_SOURCES"), _src(_P_ENTRY, "_CONNECT_SOURCES")),
        "api_connection": (_strings(_P_CONN, "SUPPORTED_PROVIDERS"), _src(_P_CONN, "SUPPORTED_PROVIDERS")),
        "scheduler": (_strings(_P_SCHED, "_SCHEDULABLE_PROVIDERS"), _src(_P_SCHED, "_SCHEDULABLE_PROVIDERS")),
        "scan_scopes": (_strings(_P_SCOPES, "CLOUD_PROVIDERS"), _src(_P_SCOPES, "CLOUD_PROVIDERS")),
        "deep_inventory_api": (_strings(_P_ROUTES, "_INVENTORY_PROVIDERS"), _src(_P_ROUTES, "_INVENTORY_PROVIDERS")),
        "cis_api": (_strings(_P_ROUTES, "_CIS_PROVIDERS"), _src(_P_ROUTES, "_CIS_PROVIDERS")),
        "benchmark_inventory": (bench_json, _src(_P_BENCH_JSON, "providers", "json")),
        "benchmark_provenance": (sorted(_benchmark_provenance()), _src(_P_BENCH_PROV, "BENCHMARK_PROVENANCE")),
        "side_scan_capabilities": (sorted(_side_scan_capabilities()), _src(_P_SIDESCAN, "side_scan_provider_capabilities")),
        "side_scan_api": (_strings(_P_ROUTES, "_SIDESCAN_PROVIDERS"), _src(_P_ROUTES, "_SIDESCAN_PROVIDERS")),
        "discovery_registry": (_dict_keys(_P_CLOUD, "_PROVIDERS"), _src(_P_CLOUD, "_PROVIDERS")),
    }
    groups = [
        ("onboarding", "Connection onboarding and scan scope", ["connect", "api_connection", "scheduler", "scan_scopes"]),
        ("inventory", "Deep inventory vs connection lists", ["deep_inventory_api", "api_connection", "scan_scopes"]),
        ("benchmarks", "Benchmark posture", ["cis_api", "benchmark_inventory", "benchmark_provenance"]),
        ("side_scan", "Side-scan", ["side_scan_capabilities", "side_scan_api"]),
        ("discovery", "Scan scope vs AI/agent discovery registry", ["scan_scopes", "discovery_registry"]),
    ]
    out = []
    for group_id, title, names in groups:
        union = sorted({p for n in names for p in lists[n][0]})
        differing = [p for p in union if not all(p in lists[n][0] for n in names)]
        if not differing:
            continue
        out.append(
            {
                "id": group_id,
                "lists": [{"members": lists[n][0], "name": n, "source": lists[n][1]} for n in names],
                "providers_not_in_every_list": differing,
                "title": title,
            }
        )
    return out


# ── Rendering ────────────────────────────────────────────────────────────────


def build() -> dict[str, Any]:
    return {
        "cloud_matrix": build_cloud_matrix(),
        "disagreements": build_disagreements(),
        "generator": SCRIPT,
        "integrations": build_integrations(),
        "schema_version": 1,
    }


def _fmt_source(src: Source) -> str:
    return f"`{src['path']}` `{src['symbol']}`"


def _fmt_item(item: Any) -> str:
    if isinstance(item, dict):
        if "family" in item:
            return f"{item['family']} ({item['rule_count']})"
        if "tool" in item:
            return f"{item['name']} (tool `{item['tool']}`, formats: {', '.join(item['formats'] or [])})"
    return str(item)


def render_markdown(data: dict[str, Any]) -> str:
    matrix = data["cloud_matrix"]
    lanes = matrix["lanes"]
    lines = [
        "# Vendor Coverage",
        "",
        "<!-- Generated by scripts/generate_vendor_coverage.py. Do not edit by hand. -->",
        "",
        "This page is generated from code constants, checked-in JSON and module files.",
        "Regenerate with `python scripts/generate_vendor_coverage.py --write`; CI and",
        "`make preflight` run `--check`. The machine-readable form, with a source for",
        "every cell, is [`VENDOR_COVERAGE.json`](VENDOR_COVERAGE.json).",
        "",
        "A cell shows what the named source declares. It does not prove a live",
        "credentialed run against that provider.",
        "",
        "## Cloud and AI-infrastructure providers",
        "",
        f"{len(matrix['rows'])} providers × {len(lanes)} lanes; {matrix['gap_count']} cells are gaps ({GAP}).",
        "",
        "Legend: `✓` declared · `—` not declared in that source · benchmark posture is",
        "`implemented/official` control count (`n/a` = official count withheld because the",
        "catalog is not vendored) · `(module)` = signal comes from a provider-specific module",
        "rather than the shared enum. The Kubernetes posture run in `src/agent_bom/k8s.py`",
        "attaches `KUBERNETES_BENCHMARK_PROVENANCE`; `benchmark_inventory.json` carries no",
        "Kubernetes control count.",
        "",
        "| Provider | " + " | ".join(lane["title"] for lane in lanes) + " |",
        "|---|" + "|".join(":-:" for _ in lanes) + "|",
    ]
    for row in matrix["rows"]:
        lines.append(f"| {row['provider']} | " + " | ".join(row["cells"][lane["id"]]["display"] for lane in lanes) + " |")

    lines += ["", "Benchmarks:", ""]
    for row in matrix["rows"]:
        value = row["cells"]["cis_posture"]["value"]
        if value:
            lines.append(f"- {row['provider']}: {value['benchmark_name']} {value['benchmark_version']}")

    lines += ["", "## Integrations by category", "", "| Category | Count | Items |", "|---|--:|---|"]
    for cat in data["integrations"]:
        items = "; ".join(_fmt_item(i) for i in cat["items"]) if cat["items"] else GAP
        if cat["id"] == "agent_clients":
            levels: dict[str, int] = {}
            for item in cat["items"]:
                levels[item["support_level"]] = levels.get(item["support_level"], 0) + 1
            items = "; ".join(f"{k}: {v}" for k, v in sorted(levels.items())) + " (full list in JSON)"
        lines.append(f"| {cat['title']} | {len(cat['items'])} | {items} |")
    notes = [f"- {cat['title']}: {cat['note']}" for cat in data["integrations"] if cat["note"]]
    if notes:
        lines += ["", "Notes:", "", *notes]

    lines += [
        "",
        "## Declared provider lists that disagree",
        "",
        "Each group compares provider lists that describe related surfaces. A provider",
        "listed below appears in at least one list of the group but not in all of them.",
        "Some differences may be intentional; each is listed so it can be confirmed or",
        "reconciled.",
        "",
    ]
    if not data["disagreements"]:
        lines.append("All compared lists agree.")
    for group in data["disagreements"]:
        names = [entry["name"] for entry in group["lists"]]
        lines += [f"### {group['title']}", "", "| Provider | " + " | ".join(f"`{n}`" for n in names) + " |"]
        lines.append("|---|" + "|".join(":-:" for _ in names) + "|")
        for provider in group["providers_not_in_every_list"]:
            marks = [YES if provider in entry["members"] else GAP for entry in group["lists"]]
            lines.append(f"| {provider} | " + " | ".join(marks) + " |")
        lines += ["", "Lists: " + "; ".join(f"`{e['name']}` = {_fmt_source(e['source'])}" for e in group["lists"]), ""]

    lines += ["## Sources", "", "Provider lanes:", ""]
    for lane in lanes:
        lines.append(f"- {lane['title']}: {_fmt_source(lane['source'])}")
    lines += [
        f"- Benchmark names and versions: `{_P_BENCH_PROV}` `BENCHMARK_PROVENANCE`, `KUBERNETES_BENCHMARK_PROVENANCE`",
        f"- AWS identity signal: `{_P_AWS_IAM}` (module present)",
        "",
        "Integration categories:",
        "",
    ]
    for cat in data["integrations"]:
        lines.append(f"- {cat['title']}: " + ", ".join(_fmt_source(s) for s in cat["sources"]))
    return "\n".join(lines) + "\n"


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Write docs/VENDOR_COVERAGE.md and .json")
    mode.add_argument("--check", action="store_true", help="Exit 1 if either generated file is stale")
    args = parser.parse_args(argv)

    data = build()
    expected = {DOC_MD: render_markdown(data), DOC_JSON: render_json(data)}

    if args.write:
        for path, text in expected.items():
            path.write_text(text, encoding="utf-8")
        return 0

    stale = False
    for path, text in expected.items():
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != text:
            stale = True
            rel = path.relative_to(ROOT).as_posix()
            diff = list(
                difflib.unified_diff(current.splitlines(), text.splitlines(), f"{rel} (committed)", f"{rel} (expected)", lineterm="")
            )
            print(f"{rel} is stale.", file=sys.stderr)
            print("\n".join(diff[:40]), file=sys.stderr)
    if stale:
        print(f"Run `python {SCRIPT} --write` and commit the result.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
