"""Native block-volume initialization contracts; no Snowflake account required."""

import importlib.util
import os
import secrets
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "deploy/snowflake/native-app/container-entrypoint.py"


@pytest.fixture
def entrypoint():
    spec = importlib.util.spec_from_file_location("native_entrypoint", ENTRYPOINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_service_uses_dedicated_encrypted_persistent_mount():
    spec = yaml.safe_load((ROOT / "deploy/snowflake/native-app/service-spec.yaml").read_text())
    api, ui = spec["spec"]["containers"]
    volume = next(v for v in spec["spec"]["volumes"] if v["name"] == "evidence")
    assert volume["source"] == "block"
    assert volume["size"] == "4Gi"
    assert volume["blockConfig"]["encryption"] == "SNOWFLAKE_FULL"
    assert volume["blockConfig"]["snapshotOnDelete"] is True
    assert {"name": "evidence", "mountPath": "/var/lib/agent-bom"} in api["volumeMounts"]
    assert not ui.get("volumeMounts")
    assert api["env"]["AGENT_BOM_DB"] == api["env"]["AGENT_BOM_GRAPH_DB"]
    assert api["env"]["AGENT_BOM_REQUIRE_AUDIT_HMAC"] == "1"
    setup = (ROOT / "deploy/snowflake/native-app/scripts/setup.sql").read_text()
    core = setup.split("CREATE SERVICE IF NOT EXISTS core.agent_bom_api", 1)[1].split(";", 1)[0]
    assert "MIN_INSTANCES = 1" in core and "MAX_INSTANCES = 1" in core
    images = yaml.safe_load((ROOT / "deploy/snowflake/native-app/images.yml").read_text())["images"]
    assert images[0]["dockerfile"] == "deploy/docker/Dockerfile.native-app"
    assert '"deploy/docker/Dockerfile.native-app"' in (ROOT / "scripts/bump-version.py").read_text()
    assert '"deploy/docker/Dockerfile.native-app"' in (ROOT / "scripts/check_docker_base_policy.py").read_text()
    assert "USER abom" in (ROOT / "deploy/docker/Dockerfile.snowpark").read_text()


def test_native_refuses_unmounted_directory(entrypoint, monkeypatch):
    monkeypatch.setattr(entrypoint.os, "getuid", lambda: 0)
    monkeypatch.setattr(entrypoint.os.path, "ismount", lambda _: False)
    with pytest.raises(RuntimeError, match="mounted"):
        entrypoint.prepare_state()


@pytest.fixture
def prepared_runtime(entrypoint, monkeypatch, tmp_path):
    """Exercise real files; simulate privilege syscalls without changing pytest uid."""
    # prepare_state writes os.environ directly; isolate additions even when
    # a variable was absent before the test (delenv alone cannot restore it).
    monkeypatch.setattr(entrypoint.os, "environ", dict(os.environ))
    entrypoint.STATE = str(tmp_path)
    entrypoint.UID = os.getuid()
    entrypoint.GID = os.getgid()
    state = {"uid": 0, "gid": 0, "groups": [1]}
    calls = []
    monkeypatch.setattr(entrypoint.os.path, "ismount", lambda _: True)
    monkeypatch.setattr(entrypoint.os, "getuid", lambda: state["uid"])
    monkeypatch.setattr(entrypoint.os, "getgid", lambda: state["gid"])
    monkeypatch.setattr(entrypoint.os, "getgroups", lambda: state["groups"])
    for name, key in (("setgroups", "groups"), ("setgid", "gid"), ("setuid", "uid")):

        def update(value, name=name, key=key):
            calls.append(name)
            state[key] = value

        monkeypatch.setattr(entrypoint.os, name, update)
    monkeypatch.setattr(entrypoint.os, "fchown", lambda *_: calls.append("fchown"))
    monkeypatch.setattr(entrypoint.os, "umask", lambda *_: None)
    for name in (
        "AGENT_BOM_DB",
        "AGENT_BOM_GRAPH_DB",
        "AGENT_BOM_STATE_DIR",
        "AGENT_BOM_AUDIT_HMAC_KEY_FILE",
        "AGENT_BOM_REQUIRE_AUDIT_HMAC",
        "AGENT_BOM_CONTROL_PLANE_REPLICAS",
    ):
        monkeypatch.delenv(name, raising=False)
    return entrypoint, state, calls


def test_restart_retains_signing_key_and_drops_groups_before_api(prepared_runtime):
    entrypoint, state, calls = prepared_runtime
    entrypoint.prepare_state()
    key = Path(entrypoint.STATE, "audit-hmac.key")
    first = key.read_bytes()
    assert len(first) == 64
    assert key.stat().st_mode & 0o777 == 0o600
    assert calls == ["fchown", "setgroups", "setgid", "setuid"]
    state["uid"] = 0
    entrypoint.prepare_state()
    assert key.read_bytes() == first


def test_key_symlink_is_not_followed(prepared_runtime, tmp_path):
    entrypoint, _, _ = prepared_runtime
    target = tmp_path / "untouched"
    target.write_text("unchanged")
    (tmp_path / "audit-hmac.key").symlink_to(target)
    with pytest.raises(OSError):
        entrypoint.prepare_state()
    assert target.read_text() == "unchanged"


def test_failed_privilege_drop_prevents_initialization(prepared_runtime, monkeypatch):
    entrypoint, _, _ = prepared_runtime
    monkeypatch.setattr(entrypoint.os, "setuid", lambda _: (_ for _ in ()).throw(PermissionError()))
    with pytest.raises(PermissionError):
        entrypoint.prepare_state()
    assert not Path(entrypoint.STATE, "audit-hmac.key").exists()


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_TEST_NATIVE_IMAGE"), reason="requires explicitly built Native App Docker image")
def test_native_docker_replacement_preserves_tenant_graph_and_audit():
    """Real image/root-init/drop, named-volume replacement, and signed audit read."""
    image = os.environ["AGENT_BOM_TEST_NATIVE_IMAGE"]
    name = "agent-bom-native-test-" + secrets.token_hex(5)
    env = dict(os.environ, AGENT_BOM_API_KEY=secrets.token_hex(32))

    def docker(*args, input=None, check=True):
        return subprocess.run(["docker", *args], input=input, text=True, capture_output=True, check=check, env=env, timeout=90)

    def start():
        docker("run", "-d", "--name", name, "-e", "AGENT_BOM_API_KEY", "-v", f"{name}:/var/lib/agent-bom", image)
        for _ in range(40):
            result = docker(
                "exec", name, "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8422/health')", check=False
            )
            if result.returncode == 0:
                return
            time.sleep(0.25)
        pytest.fail("Native image did not become healthy")

    def probe(code):
        return docker(
            "exec",
            "-i",
            "--user",
            "10001:10001",
            "-e",
            "AGENT_BOM_DB=/var/lib/agent-bom/control-plane.db",
            "-e",
            "AGENT_BOM_AUDIT_HMAC_KEY_FILE=/var/lib/agent-bom/audit-hmac.key",
            name,
            "/app/.venv/bin/python",
            "-",
            input=textwrap.dedent(code),
        )

    try:
        docker("volume", "create", name)
        start()
        probe("""
            import os
            from pathlib import Path
            from agent_bom.db.graph_store import open_graph_db, save_graph
            from agent_bom.graph.container import UnifiedGraph
            from agent_bom.graph.node import UnifiedNode
            from agent_bom.graph.edge import UnifiedEdge
            from agent_bom.graph.types import EntityType, RelationshipType
            from agent_bom.api.audit_log import get_audit_log, AuditEntry
            status = Path('/proc/1/status').read_text()
            assert 'Uid:\\t10001\\t10001\\t10001\\t10001' in status
            assert 'Gid:\\t10001\\t10001\\t10001\\t10001' in status
            assert next(line for line in status.splitlines() if line.startswith('Groups:')).strip() == 'Groups:'
            graph = UnifiedGraph(scan_id='persisted', tenant_id='tenant-a')
            graph.add_node(UnifiedNode(id='agent:a', entity_type=EntityType.AGENT, label='A'))
            graph.add_node(UnifiedNode(id='server:s', entity_type=EntityType.SERVER, label='S'))
            graph.add_edge(UnifiedEdge(source='agent:a', target='server:s', relationship=RelationshipType.USES))
            with open_graph_db(os.environ['AGENT_BOM_DB']) as conn:
                save_graph(conn, graph)
            get_audit_log().append(AuditEntry(action='persistence-test', details={'tenant_id':'tenant-a'}))
        """)
        docker("rm", "-f", name)
        start()
        probe("""
            import os
            import urllib.error
            import urllib.request
            from agent_bom.db.graph_store import open_graph_db, load_graph
            from agent_bom.api.audit_log import get_audit_log
            from agent_bom.api.connection_store import get_connection_store, SQLiteConnectionStore
            with open_graph_db(os.environ['AGENT_BOM_DB']) as conn:
                graph = load_graph(conn, tenant_id='tenant-a', scan_id='persisted')
                assert len(graph.nodes) == 2 and len(graph.edges) == 1
                other = load_graph(conn, tenant_id='tenant-b', scan_id='persisted')
                assert len(other.nodes) == 0
            valid, invalid = get_audit_log().verify_integrity(tenant_id='tenant-a')
            assert valid >= 1 and invalid == 0
            assert isinstance(get_connection_store(), SQLiteConnectionStore)
            try:
                urllib.request.urlopen('http://localhost:8422/v1/scan')
            except urllib.error.HTTPError as exc:
                assert exc.code in {401,403}
            else:
                raise AssertionError('anonymous API request was accepted')
        """)
    finally:
        docker("rm", "-f", name, check=False)
        docker("volume", "rm", name, check=False)


def test_failed_key_write_never_publishes_empty_key(prepared_runtime, monkeypatch):
    entrypoint, state, _ = prepared_runtime
    original_fsync = entrypoint.os.fsync
    monkeypatch.setattr(entrypoint.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("write interrupted")))
    with pytest.raises(OSError):
        entrypoint.prepare_state()
    assert not Path(entrypoint.STATE, "audit-hmac.key").exists()
    monkeypatch.setattr(entrypoint.os, "fsync", original_fsync)
    state["uid"] = 0
    entrypoint.prepare_state()
    assert len(Path(entrypoint.STATE, "audit-hmac.key").read_bytes()) == 64


def test_key_is_complete_before_atomic_publication(prepared_runtime, monkeypatch):
    entrypoint, _, _ = prepared_runtime
    original_rename = entrypoint.os.rename
    published = []

    def checked_rename(source, target, **kwargs):
        assert len(Path(entrypoint.STATE, source).read_bytes()) == 64
        assert not Path(entrypoint.STATE, target).exists()
        published.append(target)
        return original_rename(source, target, **kwargs)

    monkeypatch.setattr(entrypoint.os, "rename", checked_rename)
    entrypoint.prepare_state()
    assert published == ["audit-hmac.key"]
    assert Path(entrypoint.STATE, "audit-hmac.key").stat().st_nlink == 1


def test_concurrent_initializers_keep_one_complete_key(tmp_path):
    script = """
import hashlib, importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location("entrypoint", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.STATE = sys.argv[2]
module.UID = os.getuid()
module._prepare_audit_key()
print(hashlib.sha256(pathlib.Path(module.STATE, "audit-hmac.key").read_bytes()).hexdigest())
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(ENTRYPOINT), str(tmp_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for _ in range(4)
    ]
    outputs = []
    for process in processes:
        output, error = process.communicate(timeout=15)
        assert process.returncode == 0, error
        outputs.append(output.strip())
    assert len(set(outputs)) == 1
    assert len((tmp_path / "audit-hmac.key").read_bytes()) == 64
    assert not list(tmp_path.glob(".audit-key-*"))
