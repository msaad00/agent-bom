"""Deterministic characterization snapshots for the AWS, Azure and GCP CIS benchmarks.

Every ``_check_*`` function each benchmark module defines is driven directly
against a fixed set of fake SDK clients, and each provider's ``run_benchmark``
runs end to end against the same fakes. The complete result objects (every
dataclass field, in emission order) are recorded so a structural refactor can
prove byte-identical behaviour. No network access: every SDK entry point the
checks reach is replaced with an in-process fake.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
import types
from contextlib import ExitStack, contextmanager
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import MagicMock, patch

import pytest

SCENARIOS = ("mock", "empty", "error", "denied")
PROVIDERS = ("aws", "azure", "gcp")
_ADDR = re.compile(r"id='\d+'|id=\d+|0x[0-9a-fA-F]+")
_CHECK_NAME = re.compile(r"_check_\d+(?:_\d+)*")


class _Empty:
    """A response that is empty in every shape a check may read."""

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return _Empty()

    def __call__(self, *args: Any, **kwargs: Any) -> _Empty:
        return _Empty()

    def __iter__(self) -> Iterator[Any]:
        return iter(())

    def __getitem__(self, key: Any) -> _Empty:
        return _Empty()

    def get(self, key: Any, default: Any = None) -> Any:
        return default

    def __bool__(self) -> bool:
        return False

    def __len__(self) -> int:
        return 0

    def __contains__(self, item: Any) -> bool:
        return False

    def __repr__(self) -> str:
        return "<Empty>"


class _DeniedError(Exception):
    """Provider-neutral permission failure (HTTP 403 + AccessDenied code)."""

    status_code = 403
    code = 403
    reason = "IAM_PERMISSION_DENIED"
    response = {"Error": {"Code": "AccessDenied", "Message": "scenario denied"}}

    def __init__(self) -> None:
        super().__init__("AccessDenied: scenario denied (403)")
        self.resp = types.SimpleNamespace(status=403)


def _aws_denied() -> Exception:
    try:
        from botocore.exceptions import ClientError
    except ImportError:  # pragma: no cover - aws extra installed in CI
        return _DeniedError()
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "scenario denied"}}, "ScenarioOperation")


class _Raising:
    """Every call, iteration or subscript raises the scenario exception."""

    def __init__(self, factory: Callable[[], Exception]) -> None:
        self._factory = factory

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        return _Raising(self._factory)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise self._factory()

    def __iter__(self) -> Iterator[Any]:
        raise self._factory()

    def __getitem__(self, key: Any) -> Any:
        raise self._factory()

    def __repr__(self) -> str:
        return "<Raising>"


def _client(scenario: str, provider: str) -> Any:
    if scenario == "mock":
        return MagicMock(name=f"{provider}-client")
    if scenario == "empty":
        return _Empty()
    if scenario == "error":
        return _Raising(lambda: RuntimeError("scenario boom"))
    if scenario == "denied":
        return _Raising(_aws_denied if provider == "aws" else _DeniedError)
    raise ValueError(scenario)


def _normalize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _normalize(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, dict):
        return {str(_normalize(k)): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return _ADDR.sub("<addr>", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _ADDR.sub("<addr>", repr(value))


def _check_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in name.removeprefix("_check_").split("_"))


def check_functions(module: types.ModuleType) -> list[str]:
    """Every CIS check function the module exposes, in numeric order."""
    names = [name for name in vars(module) if _CHECK_NAME.fullmatch(name) and callable(getattr(module, name))]
    return sorted(names, key=_check_key)


def _call(fn: Callable[..., Any], client: Any, ids: dict[str, str]) -> Any:
    args = []
    for param in inspect.signature(fn).parameters.values():
        if param.kind is param.KEYWORD_ONLY:
            continue
        args.append(ids.get(param.name, client))
    return fn(*args)


def _outcome(fn: Callable[[], Any]) -> Any:
    try:
        return {"result": _normalize(fn())}
    except Exception as exc:  # noqa: BLE001 - raising is part of the recorded contract
        return {"raised": type(exc).__name__, "message": _ADDR.sub("<addr>", str(exc))}


def _stub_module(name: str, factory: Callable[..., Any]) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__getattr__ = lambda attr: factory  # type: ignore[method-assign]
    return module


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


def _aws_session(scenario: str, *, sts_ok: bool) -> Any:
    client = _client(scenario, "aws")
    sts = MagicMock(name="sts")
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    if not sts_ok:
        sts.get_caller_identity.side_effect = RuntimeError("sts unavailable")
    session = MagicMock(name="session")
    session.region_name = "us-east-1"
    session.client.side_effect = lambda svc, **_kw: sts if svc == "sts" else client
    return session


def _aws_snapshot() -> dict[str, Any]:
    from agent_bom.cloud import aws_cis_benchmark as mod

    ids = {"account_id": "123456789012"}
    direct = {
        scenario: {name: _outcome(lambda n=name, s=scenario: _call(getattr(mod, n), _client(s, "aws"), ids)) for name in check_functions(mod)}
        for scenario in SCENARIOS
    }
    runs = {}
    for scenario in SCENARIOS:
        for sts_ok in (True, False):
            key = f"{scenario}/sts={'ok' if sts_ok else 'fail'}"
            runs[key] = _outcome(lambda s=scenario, ok=sts_ok: mod.run_benchmark(session=_aws_session(s, sts_ok=ok)).to_dict())
    for scenario in ("mock", "error"):
        runs[f"all_regions/{scenario}"] = _outcome(
            lambda s=scenario: mod.run_benchmark_all_regions(regions=["us-east-1", "eu-west-1"], session=_aws_session(s, sts_ok=True)).to_dict()
        )
    return {"check_functions": check_functions(mod), "direct": direct, "run_benchmark": runs}


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

_AZURE_SDK_MODULES = (
    "azure.identity",
    "azure.keyvault.keys",
    "azure.keyvault.secrets",
    "azure.mgmt.authorization",
    "azure.mgmt.storage",
    "azure.mgmt.monitor",
    "azure.mgmt.network",
    "azure.mgmt.security",
    "azure.mgmt.sql",
    "azure.mgmt.compute",
    "azure.mgmt.keyvault",
    "azure.mgmt.rdbms.mysql",
    "azure.mgmt.rdbms.postgresql",
    "azure.mgmt.web",
)


@contextmanager
def _azure_sdk(scenario: str) -> Iterator[None]:
    from agent_bom.cloud import azure_cis_benchmark as mod

    client = _client(scenario, "azure")

    def _factory(*_args: Any, **_kwargs: Any) -> Any:
        return client

    def _diagnostics(credential: Any, subscription_id: str) -> Any:
        if scenario == "error":
            raise RuntimeError("scenario boom")
        if scenario == "denied":
            raise _DeniedError()
        return [] if scenario == "empty" else [{"properties": {"logs": [{"category": "Administrative", "enabled": True}]}}]

    with ExitStack() as stack:
        stack.enter_context(patch.dict(sys.modules, {name: _stub_module(name, _factory) for name in _AZURE_SDK_MODULES}))
        stack.enter_context(patch("agent_bom.cloud.azure_graph.AzureGraphClient", _factory))
        stack.enter_context(patch.object(mod, "_list_subscription_diagnostic_settings", _diagnostics))
        yield


def _azure_snapshot() -> dict[str, Any]:
    from agent_bom.cloud import azure_cis_benchmark as mod

    ids = {"subscription_id": "00000000-0000-0000-0000-000000000001"}
    direct = {}
    for scenario in SCENARIOS:
        with _azure_sdk(scenario):
            direct[scenario] = {
                name: _outcome(lambda n=name, s=scenario: _call(getattr(mod, n), _client(s, "azure"), ids)) for name in check_functions(mod)
            }
    runs = {}
    for scenario in SCENARIOS:
        with _azure_sdk(scenario):
            runs[scenario] = _outcome(lambda: mod.run_benchmark(subscription_id=ids["subscription_id"], credential=object()).to_dict())
    return {"check_functions": check_functions(mod), "direct": direct, "run_benchmark": runs}


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------


@contextmanager
def _gcp_sdk(scenario: str) -> Iterator[None]:
    from agent_bom.cloud import gcp_cis_benchmark as mod

    client = _client(scenario, "gcp")

    def _factory(*_args: Any, **_kwargs: Any) -> Any:
        return client

    with ExitStack() as stack:
        stack.enter_context(patch.object(mod, "_discovery_client", _factory))
        stack.enter_context(patch.object(mod, "_import_google_cloud_module", lambda name: _stub_module(f"google.cloud.{name}", _factory)))
        yield


def _gcp_snapshot() -> dict[str, Any]:
    from agent_bom.cloud import gcp_cis_benchmark as mod

    ids = {"project_id": "characterization-project"}
    direct = {}
    for scenario in SCENARIOS:
        with _gcp_sdk(scenario):
            direct[scenario] = {name: _outcome(lambda n=name, s=scenario: _call(getattr(mod, n), _client(s, "gcp"), ids)) for name in check_functions(mod)}
    runs = {}
    for scenario in SCENARIOS:
        with _gcp_sdk(scenario):
            runs[scenario] = _outcome(lambda: mod.run_benchmark(project_id=ids["project_id"], credentials=object()).to_dict())
    return {"check_functions": check_functions(mod), "direct": direct, "run_benchmark": runs}


SNAPSHOTS: dict[str, Callable[[], dict[str, Any]]] = {"aws": _aws_snapshot, "azure": _azure_snapshot, "gcp": _gcp_snapshot}


def emitted_check_ids(snapshot: dict[str, Any]) -> dict[str, set[str]]:
    """Map every check id seen in the snapshot to the statuses it produced."""
    statuses: dict[str, set[str]] = {}

    def _visit(outcome: Any) -> None:
        result = outcome.get("result") if isinstance(outcome, dict) else None
        if isinstance(result, dict) and "check_id" in result:
            statuses.setdefault(result["check_id"], set()).add(result["status"])
        elif isinstance(result, dict) and "checks" in result:
            for check in result["checks"]:
                statuses.setdefault(check["check_id"], set()).add(check["status"])

    for per_scenario in snapshot["direct"].values():
        for outcome in per_scenario.values():
            _visit(outcome)
    for outcome in snapshot["run_benchmark"].values():
        _visit(outcome)
    return statuses


# ---------------------------------------------------------------------------
# Golden comparison
# ---------------------------------------------------------------------------

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cis_characterization"


def _dump(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=1, sort_keys=True) + "\n"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_cis_benchmark_matches_characterization_golden(provider: str) -> None:
    with patch("time.sleep"):
        snapshot = SNAPSHOTS[provider]()
    golden = GOLDEN_DIR / f"{provider}.json"
    if os.environ.get("AGENT_BOM_UPDATE_CIS_GOLDEN") == "1":
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(_dump(snapshot))
    assert _dump(snapshot) == golden.read_text()


@pytest.mark.parametrize("provider", PROVIDERS)
def test_characterization_covers_every_registered_check(provider: str) -> None:
    """Every check the runner registers is exercised, and every check function is driven directly."""
    snapshot = json.loads((GOLDEN_DIR / f"{provider}.json").read_text())
    statuses = emitted_check_ids(snapshot)
    full_run = snapshot["run_benchmark"]["mock/sts=ok" if provider == "aws" else "mock"]["result"]
    registered = {check["check_id"] for check in full_run["checks"]}
    assert registered, "full run emitted no checks"
    assert registered <= set(statuses)
    for per_scenario in snapshot["direct"].values():
        assert set(per_scenario) == set(snapshot["check_functions"])
    seen = set().union(*statuses.values())
    assert {"fail", "error"} <= seen
