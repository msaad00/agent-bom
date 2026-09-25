"""Demo estate data must never mix with operator product data.

The demo bootstrap seeds a synthetic estate into whatever local stores the
process resolves. These tests pin the contract that demo mode resolves every
local store under a dedicated demo state directory, that the bootstrap fails
closed when that isolation is missing or the store already holds non-demo
evidence, and that the test suite itself never resolves the real home.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agent_bom.storage import state_home

# ── Test-suite isolation (the suite must never touch the real home) ──────────


def test_suite_home_and_state_dir_are_temporary() -> None:
    tmp_root = Path(tempfile.gettempdir()).resolve()
    home = Path.home().resolve()
    assert home.is_relative_to(tmp_root), home
    assert state_home.state_dir().resolve().is_relative_to(tmp_root)


def test_suite_default_store_paths_are_temporary() -> None:
    from agent_bom.asset_tracker import default_assets_db_path
    from agent_bom.db.graph_store import default_graph_db_path
    from agent_bom.db.local_analytics import local_analytics_path
    from agent_bom.history import history_dir

    tmp_root = Path(tempfile.gettempdir()).resolve()
    for path in (default_assets_db_path(), default_graph_db_path(), local_analytics_path(), history_dir()):
        assert Path(path).resolve().is_relative_to(tmp_root), path


# ── Resolver contract ────────────────────────────────────────────────────────


def test_state_dir_defaults_to_home_and_honors_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AGENT_BOM_STATE_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert state_home.state_dir() == tmp_path / ".agent-bom"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "custom"))
    assert state_home.state_dir() == tmp_path / "custom"


def test_activation_is_a_no_op_outside_demo_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    assert state_home.activate_demo_state_dir() is None
    assert state_home.state_dir() == tmp_path / "product"


def test_demo_state_dir_nests_under_product_state_and_is_idempotent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    assert not state_home.demo_state_isolated()

    demo_dir = state_home.activate_demo_state_dir()

    assert demo_dir == tmp_path / "product" / "demo-estate"
    assert state_home.state_dir() == demo_dir
    assert state_home.demo_state_isolated()
    # A second activation (uvicorn worker re-import, lifespan after CLI) must
    # not nest demo-estate/demo-estate.
    assert state_home.activate_demo_state_dir() == demo_dir
    assert state_home.state_dir() == demo_dir


def test_explicit_demo_state_dir_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    monkeypatch.setenv("AGENT_BOM_DEMO_STATE_DIR", str(tmp_path / "elsewhere"))
    assert state_home.activate_demo_state_dir() == tmp_path / "elsewhere"
    assert state_home.state_dir() == tmp_path / "elsewhere"


def test_demo_state_dir_refuses_the_product_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.delenv("AGENT_BOM_STATE_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_DEMO_STATE_DIR", str(tmp_path / ".agent-bom"))
    with pytest.raises(ValueError, match="product state"):
        state_home.activate_demo_state_dir()


@pytest.mark.parametrize("var", ["AGENT_BOM_DB", "AGENT_BOM_GRAPH_DB", "AGENT_BOM_LOCAL_ANALYTICS_DB"])
def test_demo_refuses_explicit_store_paths_inside_the_product_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, var: str) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    monkeypatch.setenv(var, str(tmp_path / "product" / "control-plane.db"))
    with pytest.raises(ValueError, match=var):
        state_home.activate_demo_state_dir()


def test_demo_allows_explicit_store_paths_outside_the_product_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo-only.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", "postgresql://demo@db/demo")
    assert state_home.activate_demo_state_dir() == tmp_path / "product" / "demo-estate"


def test_every_default_local_store_follows_the_demo_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("AGENT_BOM_DB", "AGENT_BOM_GRAPH_DB", "AGENT_BOM_LOCAL_ANALYTICS_DB", "AGENT_BOM_DEMO_STATE_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    demo_dir = state_home.activate_demo_state_dir()
    assert demo_dir is not None

    from agent_bom import scan_cache
    from agent_bom.api import durable_store
    from agent_bom.api.report_worker import report_artifact_root
    from agent_bom.asset_tracker import default_assets_db_path
    from agent_bom.db import local_analytics
    from agent_bom.db.graph_store import default_graph_db_path
    from agent_bom.history import history_dir
    from agent_bom.scan_delta import default_baseline_path

    monkeypatch.setattr(local_analytics, "LOCAL_ANALYTICS_DB", "")
    paths = {
        "graph": default_graph_db_path(),
        "control_plane": Path(durable_store.default_state_db_path(create_parent=False)),
        "assets": default_assets_db_path(),
        "analytics": local_analytics.local_analytics_path(),
        "history": history_dir(create=False),
        "baseline": default_baseline_path(),
        "report_artifacts": report_artifact_root(),
        "scan_cache": scan_cache.default_cache_path(),
    }
    for name, path in paths.items():
        assert Path(path).is_relative_to(demo_dir), f"{name} resolved outside the demo dir: {path}"


def test_default_graph_scenario_store_follows_the_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_bom.api import stores

    for var in ("AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(stores, "_graph_scenario_store", None)

    store = stores._get_graph_scenario_store()

    assert Path(store._db_path).is_relative_to(tmp_path / "state")  # type: ignore[attr-defined]
    assert list(cwd.iterdir()) == []


# ── Bootstrap fails closed ───────────────────────────────────────────────────


def test_bootstrap_refuses_to_seed_without_isolated_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.demo_estate.bootstrap import get_demo_estate_bootstrap_status, maybe_bootstrap_demo_estate

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    graph_store = SQLiteGraphStore(tmp_path / "product-graph.db")
    monkeypatch.setattr(api_stores, "_graph_store", graph_store)

    summary = maybe_bootstrap_demo_estate()

    assert summary["seeded"] is False
    assert summary["blocked"] == "demo_state_not_isolated"
    assert get_demo_estate_bootstrap_status()["blocked"] == "demo_state_not_isolated"
    assert not (tmp_path / "product-graph.db").exists() or graph_store.latest_snapshot_id(tenant_id="default") in (None, "")


def _save_operator_graph(store, scan_id: str = "operator-scan") -> None:
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default", created_at="2099-01-01T00:00:00+00:00")
    graph.add_node(UnifiedNode(id="agent:operator", entity_type=EntityType.AGENT, label="/Users/operator/real/path"))
    store.save_graph(graph)


def test_bootstrap_refuses_a_store_holding_non_demo_snapshots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate, refresh_demo_daily_evidence, reset_daily_evidence_day
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_SCAN_ID

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    state_home.activate_demo_state_dir()
    graph_store = SQLiteGraphStore(tmp_path / "shared-graph.db")
    _save_operator_graph(graph_store)
    monkeypatch.setattr(api_stores, "_graph_store", graph_store)

    summary = maybe_bootstrap_demo_estate()

    assert summary["seeded"] is False
    assert summary["blocked"] == "non_demo_snapshot_present"
    stats = graph_store.snapshot_stats(tenant_id="default", scan_id=SHOWCASE_SCAN_ID)
    assert int(stats.get("total_nodes") or 0) == 0, "showcase must not be written beside operator evidence"
    reset_daily_evidence_day()
    assert refresh_demo_daily_evidence()["reason"] == "blocked"


def test_demo_status_never_names_an_operator_snapshot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.routes.demo_estate import _build_demo_estate_status

    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    graph_store = SQLiteGraphStore(tmp_path / "shared-graph.db")
    _save_operator_graph(graph_store)
    monkeypatch.setattr(api_stores, "_graph_store", graph_store)

    status = _build_demo_estate_status("default").model_dump()

    assert status["graph_alignment"] == "blocked"
    assert status["reason"] == "non_demo_snapshot_present"
    assert status["graph_owner_scan_id"] is None
    assert "operator-scan" not in json.dumps(status)


# ── End-to-end: a real process with a populated product home ─────────────────

_PRODUCT_SEED = """
from datetime import datetime, timezone
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.asset_tracker import AssetTracker
from agent_bom.db.graph_store import default_graph_db_path
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

graph = UnifiedGraph(scan_id="operator-scan", tenant_id="default", created_at=datetime.now(timezone.utc).isoformat())
graph.add_node(UnifiedNode(id="agent:operator", entity_type=EntityType.AGENT, label="operator"))
SQLiteGraphStore(default_graph_db_path()).save_graph(graph)
with AssetTracker() as tracker:
    tracker._conn.execute(
        "INSERT INTO assets (tenant_id, vuln_id, package, ecosystem, first_seen, last_seen)"
        " VALUES ('default', 'CVE-2099-0001', 'real-pkg', 'pypi', 'x', 'x')"
    )
    tracker._conn.commit()
"""

_DEMO_BOOT = """
import json
import agent_bom.api.server  # noqa: F401  -- import-time activation, as uvicorn does
from agent_bom.storage import state_home
from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

summary = maybe_bootstrap_demo_estate()
print(json.dumps({"state_dir": str(state_home.state_dir()), "graph_seeded": summary.get("graph_seeded"),
                  "blocked": summary.get("blocked")}))
"""


def _fingerprint(root: Path, *, exclude: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_relative_to(exclude):
            out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _clean_env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_")}
    env["HOME"] = str(home)
    env["AGENT_BOM_ALLOW_UNAUTHENTICATED_API"] = "1"
    return env


def test_demo_bootstrap_leaves_a_populated_product_home_untouched(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    product_dir = home / ".agent-bom"
    env = _clean_env(home)
    subprocess.run([sys.executable, "-c", _PRODUCT_SEED], env=env, check=True, capture_output=True, text=True)
    demo_dir = product_dir / "demo-estate"
    before = _fingerprint(product_dir, exclude=demo_dir)
    assert "db/graph.db" in before and "assets.db" in before

    demo_env = dict(env, AGENT_BOM_DEMO_ESTATE="1")
    proc = subprocess.run([sys.executable, "-c", _DEMO_BOOT], env=demo_env, check=True, capture_output=True, text=True)
    result = json.loads(proc.stdout.strip().splitlines()[-1])

    assert result["state_dir"] == str(demo_dir)
    assert result["blocked"] is None
    assert result["graph_seeded"] is True
    assert _fingerprint(product_dir, exclude=demo_dir) == before, "demo bootstrap modified the operator's product stores"

    with sqlite3.connect(product_dir / "db" / "graph.db") as conn:
        scan_ids = {row[0] for row in conn.execute("SELECT DISTINCT scan_id FROM graph_snapshots")}
    assert scan_ids == {"operator-scan"}
    with sqlite3.connect(demo_dir / "db" / "graph.db") as conn:
        demo_scan_ids = {row[0] for row in conn.execute("SELECT DISTINCT scan_id FROM graph_snapshots")}
    assert "showcase" in demo_scan_ids and "operator-scan" not in demo_scan_ids


# ── Shipped pilot wiring ─────────────────────────────────────────────────────

_ROOT = Path(__file__).resolve().parents[1]


def test_pilot_compose_persist_path_is_switchable_for_demo_mode() -> None:
    """The pilot's jobs DB lives in the product state dir, so demo pilots must be able to move it."""
    import yaml

    data = yaml.safe_load((_ROOT / "deploy" / "docker-compose.pilot.yml").read_text(encoding="utf-8"))
    command = data["services"]["api"]["command"]
    assert "--persist ${AGENT_BOM_PILOT_JOBS_DB:-/home/abom/.agent-bom/jobs.db}" in command


def test_installer_moves_the_pilot_jobs_db_into_the_demo_dir() -> None:
    script = (_ROOT / "scripts" / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "AGENT_BOM_PILOT_JOBS_DB=/home/abom/.agent-bom/demo-estate/jobs.db" in script


def test_demo_state_dir_accepts_the_pilot_demo_jobs_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AGENT_BOM_STATE_DIR", raising=False)
    monkeypatch.delenv("AGENT_BOM_DEMO_STATE_DIR", raising=False)
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / ".agent-bom" / "demo-estate" / "jobs.db"))
    assert state_home.activate_demo_state_dir() == tmp_path / ".agent-bom" / "demo-estate"


# ── CLI wiring ───────────────────────────────────────────────────────────────


def _cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # setenv-then-delenv registers an undo, so values the CLI writes are restored.
    for var in ("AGENT_BOM_DEMO_ESTATE", "AGENT_BOM_DB", "AGENT_BOM_DEMO_STATE_DIR", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_GRAPH_DB"):
        monkeypatch.setenv(var, "")
        monkeypatch.delenv(var)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "product"))
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)
    from agent_bom.api import stores

    monkeypatch.setattr(stores, "_store", None)


@pytest.mark.parametrize("command_name", ["serve", "api"])
def test_cli_demo_estate_pins_the_demo_data_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command_name: str) -> None:
    from click.testing import CliRunner

    from agent_bom.cli._server import api_cmd, serve_cmd

    _cli_env(monkeypatch, tmp_path)
    summaries: list[dict[str, str]] = []
    monkeypatch.setattr("agent_bom.cli._server._emit_runtime_summary", lambda title, rows: summaries.append(dict(rows)))

    command = serve_cmd if command_name == "serve" else api_cmd
    result = CliRunner().invoke(command, ["--demo-estate", "--api-key", "synthetic-test-only-key"])

    assert result.exit_code == 0, result.output
    demo_dir = tmp_path / "product" / "demo-estate"
    assert os.environ["AGENT_BOM_STATE_DIR"] == str(demo_dir)
    assert summaries[0]["Demo data"] == str(demo_dir)


@pytest.mark.parametrize("command_name", ["serve", "api"])
def test_cli_demo_estate_refuses_persist_into_product_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command_name: str) -> None:
    from click.testing import CliRunner

    from agent_bom.cli._server import api_cmd, serve_cmd

    _cli_env(monkeypatch, tmp_path)
    command = serve_cmd if command_name == "serve" else api_cmd
    product_db = tmp_path / "product" / "control-plane.db"
    result = CliRunner().invoke(command, ["--demo-estate", "--persist", str(product_db), "--api-key", "synthetic-test-only-key"])

    assert result.exit_code != 0
    assert "AGENT_BOM_DB" in result.output
    assert "demo data would mix with product data" in result.output


def test_cli_api_persist_selects_the_shared_database_like_serve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from click.testing import CliRunner

    from agent_bom.cli._server import api_cmd

    _cli_env(monkeypatch, tmp_path)
    db = tmp_path / "jobs.db"
    result = CliRunner().invoke(api_cmd, ["--persist", str(db), "--api-key", "synthetic-test-only-key"])

    assert result.exit_code == 0, result.output
    assert os.environ["AGENT_BOM_DB"] == str(db.resolve())
    from agent_bom.db.graph_store import default_graph_db_path

    assert default_graph_db_path() == db.resolve()
