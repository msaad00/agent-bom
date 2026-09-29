"""Characterization golden for the side-scan lifecycle contracts and stores.

Drives the execution record model (every legal and illegal transition,
resource registration and cleanup), each persistence backend (in-memory,
SQLite on a temp path, Postgres through a scripted fake connection) and the
store factory/reset.  The golden pins serialized records, SQL and parameters
issued to Postgres, and raised exception types/messages in order.

Regenerate with ``UPDATE_CLOUD_GOLDEN=1``.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from agent_bom.cloud import side_scan_lifecycle as lifecycle
from agent_bom.cloud.side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    InMemorySideScanStateStore,
    PostgresSideScanStateStore,
    SideScanCleanupOwnership,
    SideScanExecutionRecord,
    SideScanStateConflictError,
    SideScanTemporaryResource,
    SQLiteSideScanStateStore,
    TemporaryResourceStatus,
    get_side_scan_state_store,
    new_side_scan_execution,
    reset_side_scan_state_store,
    side_scan_provider_capabilities,
)

GOLDEN = Path(__file__).parent / "fixtures" / "cloud_characterization" / "side_scan_lifecycle.json"
FINGERPRINT = "a" * 64


def _ts(n: int) -> str:
    return f"2026-01-01T00:00:{n:02d}Z"


def _capture(log: list[object], label: str, fn: Callable[[], object]) -> object:
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the golden pins the exception contract
        log.append({"op": label, "raises": type(exc).__name__, "message": str(exc)})
        return None
    log.append({"op": label, "result": _render(result)})
    return result


def _render(value: object) -> object:
    if isinstance(value, SideScanExecutionRecord):
        return {"record": value.to_dict(), "evidence": value.to_evidence_dict(), "disposition": value.disposition}
    if isinstance(value, (list, tuple)):
        return [_render(item) for item in value]
    if isinstance(value, SideScanTemporaryResource):
        return value.to_dict()
    if isinstance(value, (ExecutionStatus, CleanupStatus, TemporaryResourceStatus)):
        return value.value
    return value


def _new(
    tenant: str, target: str, key: str, *, n: int = 0, provider: str = "aws", account: str = "111122223333"
) -> SideScanExecutionRecord:
    return new_side_scan_execution(
        tenant_id=tenant,
        provider=provider,  # type: ignore[arg-type]
        account_id=account,
        target_id=target,
        collector_id="collector-1",
        idempotency_key=key,
        request_fingerprint=FINGERPRINT,
        now=_ts(n),
    )


def _resource(record: SideScanExecutionRecord, kind: str, rid: str) -> SideScanTemporaryResource:
    return SideScanTemporaryResource(
        kind=kind,
        resource_id=rid,
        status=TemporaryResourceStatus.CREATED,
        ownership_tags=record.cleanup_ownership.required_tags(),
    )


def _model_lifecycle() -> list[object]:
    log: list[object] = []
    _capture(log, "capabilities", lambda: {k: v.to_dict() for k, v in side_scan_provider_capabilities().items()})
    base = _new("tenant-a", "i-0abc", "job-1")
    _capture(log, "new", lambda: base)
    _capture(log, "owns.exact", lambda: base.cleanup_ownership.owns(base.cleanup_ownership.required_tags()))
    _capture(log, "owns.partial", lambda: base.cleanup_ownership.owns({"agent-bom-sidescan": "true"}))
    _capture(log, "noop.transition.is_same", lambda: base.transition(now=_ts(1)) is base)

    for start in ExecutionStatus:
        for target in ExecutionStatus:
            src = base if start is ExecutionStatus.QUEUED else _force(base, status=start)
            _capture(log, f"exec.{start.value}->{target.value}", lambda s=src, t=target: s.transition(status=t, now=_ts(2)).status)
    for cstart in CleanupStatus:
        for ctarget in CleanupStatus:
            src = _force(base, cleanup_status=cstart)
            _capture(
                log,
                f"cleanup.{cstart.value}->{ctarget.value}",
                lambda s=src, t=ctarget: s.transition(cleanup_status=t, now=_ts(3)).cleanup_status,
            )

    running = _capture(log, "run", lambda: base.transition(status=ExecutionStatus.RUNNING, phase="snapshot", now=_ts(4)))
    assert isinstance(running, SideScanExecutionRecord)
    _capture(log, "bad.phase", lambda: running.transition(phase="teleport", now=_ts(4)))
    snap = _resource(running, "snapshot", "snap-1")
    disk = _resource(running, "volume", "vol-1")
    with_snap = _capture(log, "register.snap", lambda: running.register_resource(snap, now=_ts(5)))
    assert isinstance(with_snap, SideScanExecutionRecord)
    _capture(log, "register.snap.retry.is_same", lambda: with_snap.register_resource(snap, now=_ts(6)) is with_snap)
    _capture(
        log,
        "register.snap.conflict",
        lambda: with_snap.register_resource(
            SideScanTemporaryResource("snapshot", "snap-1", TemporaryResourceStatus.DELETED, snap.ownership_tags), now=_ts(6)
        ),
    )
    _capture(
        log,
        "register.foreign",
        lambda: with_snap.register_resource(
            SideScanTemporaryResource("volume", "vol-x", TemporaryResourceStatus.CREATED, {"agent-bom-sidescan": "true"}), now=_ts(6)
        ),
    )
    _capture(
        log,
        "register.extra_tags",
        lambda: with_snap.register_resource(
            SideScanTemporaryResource("volume", "vol-y", TemporaryResourceStatus.CREATED, {**snap.ownership_tags, "extra": "1"}),
            now=_ts(6),
        ),
    )
    both = _capture(log, "register.disk", lambda: with_snap.register_resource(disk, now=_ts(7)))
    assert isinstance(both, SideScanExecutionRecord)
    _capture(log, "candidates", lambda: both.cleanup_candidates())
    _capture(log, "mark.missing", lambda: both.mark_resource_cleanup("nope", status=TemporaryResourceStatus.DELETED, now=_ts(8)))
    for rstart in TemporaryResourceStatus:
        for rtarget in TemporaryResourceStatus:
            src = _force(both, resources=(_force_resource(snap, rstart), disk))
            _capture(
                log,
                f"resource.{rstart.value}->{rtarget.value}",
                lambda s=src, t=rtarget: [r.status.value for r in s.mark_resource_cleanup("snap-1", status=t, now=_ts(8)).resources],
            )
    done = _capture(
        log,
        "scan_complete",
        lambda: both.transition(
            status=ExecutionStatus.SCAN_COMPLETE,
            phase="cleanup",
            cleanup_status=CleanupStatus.PENDING,
            package_count=12,
            vulnerability_count=3,
            secret_count=1,
            config_finding_count=2,
            ioc_finding_count=0,
            warning_codes=("partial_fs",),
            now=_ts(9),
        ),
    )
    assert isinstance(done, SideScanExecutionRecord)
    _capture(log, "complete.blocked", lambda: done.transition(cleanup_status=CleanupStatus.COMPLETE, now=_ts(10)))
    cleaned = done.mark_resource_cleanup("snap-1", status=TemporaryResourceStatus.DELETED, now=_ts(10))
    cleaned = cleaned.mark_resource_cleanup("vol-1", status=TemporaryResourceStatus.DELETED, now=_ts(11))
    _capture(log, "complete", lambda: cleaned.transition(cleanup_status=CleanupStatus.COMPLETE, phase="finished", now=_ts(12)))
    _capture(log, "roundtrip", lambda: SideScanExecutionRecord.from_dict(json.loads(json.dumps(cleaned.to_dict()))) == cleaned)
    _validation_errors(log, base)
    return log


def _force(record: SideScanExecutionRecord, **changes: Any) -> SideScanExecutionRecord:
    from dataclasses import replace

    return replace(record, **changes)


def _force_resource(resource: SideScanTemporaryResource, status: TemporaryResourceStatus) -> SideScanTemporaryResource:
    from dataclasses import replace

    return replace(resource, status=status)


def _validation_errors(log: list[object], base: SideScanExecutionRecord) -> None:
    payload = base.to_dict()
    cases: dict[str, Callable[[], object]] = {
        "ownership.bad_uuid": lambda: SideScanCleanupOwnership("x", "a" * 24, "b" * 24),
        "ownership.bad_hex": lambda: SideScanCleanupOwnership(base.execution_id, "Z" * 24, "b" * 24),
        "resource.blank": lambda: SideScanTemporaryResource(" ", "r", TemporaryResourceStatus.CREATED, {}),
        "record.blank_scope": lambda: _force(base, target_id=" "),
        "record.bad_fingerprint": lambda: _force(base, request_fingerprint="xyz"),
        "record.negative_count": lambda: _force(base, package_count=-1),
        "record.bool_count": lambda: _force(base, secret_count=True),
        "record.zero_version": lambda: _force(base, state_version=0),
        "record.owner_mismatch": lambda: _force(base, execution_id="00000000-0000-0000-0000-000000000000"),
        "record.bad_provider": lambda: _force(base, provider="oci"),
        "record.bad_failure_code": lambda: _force(base, failure_code="has space"),
        "record.bad_warning": lambda: _force(base, warning_codes=("",)),
        "from_dict.schema": lambda: SideScanExecutionRecord.from_dict({**payload, "schema_version": "v0"}),
        "from_dict.owner": lambda: SideScanExecutionRecord.from_dict({**payload, "cleanup_ownership": None}),
        "from_dict.provider": lambda: SideScanExecutionRecord.from_dict({**payload, "provider": "oci"}),
        "from_dict.status": lambda: SideScanExecutionRecord.from_dict({**payload, "status": "bogus"}),
        "from_dict.version_str": lambda: SideScanExecutionRecord.from_dict({**payload, "state_version": "7"}).state_version,
        "from_dict.version_bad": lambda: SideScanExecutionRecord.from_dict({**payload, "state_version": "x"}),
        "from_dict.version_bool": lambda: SideScanExecutionRecord.from_dict({**payload, "state_version": True}),
        "from_dict.sparse": lambda: SideScanExecutionRecord.from_dict(
            {**payload, "counts": None, "resources": "x", "warning_codes": "y", "request_fingerprint": None}
        ),
    }
    for label, fn in cases.items():
        _capture(log, label, fn)


def _store_lifecycle(store: Any) -> list[object]:
    """Full lifecycle against a real (in-memory or SQLite) backend."""
    log: list[object] = []
    a1 = _new("tenant-a", "i-0001", "job-1", n=1)
    a2 = _new("tenant-a", "i-0002", "job-1", n=2, provider="azure", account="sub-1")
    a3 = _new("tenant-a", "vm-0003", "job-1", n=3, provider="gcp", account="proj-1")
    b1 = _new("tenant-b", "i-0001", "job-1", n=1)
    for label, rec in (("a1", a1), ("a2", a2), ("a3", a3), ("b1", b1)):
        _capture(log, f"create.{label}", lambda r=rec: store.create_or_get(r))
    _capture(log, "create.a1.dup", lambda: store.create_or_get(_new("tenant-a", "i-0001", "job-1", n=9)))
    _capture(log, "get.a1", lambda: store.get(tenant_id="tenant-a", execution_id=a1.execution_id))
    _capture(log, "get.a1.as_b", lambda: store.get(tenant_id="tenant-b", execution_id=a1.execution_id))
    _capture(log, "get.b1", lambda: store.get(tenant_id="tenant-b", execution_id=b1.execution_id))

    running = a1.transition(status=ExecutionStatus.RUNNING, phase="snapshot", now=_ts(10))
    _capture(log, "save.run", lambda: store.save(running, expected_version=a1.state_version))
    _capture(log, "save.run.stale", lambda: store.save(running, expected_version=a1.state_version))
    _capture(log, "save.skip_version", lambda: store.save(running, expected_version=a1.state_version + 5))
    _capture(
        log,
        "save.cross_tenant",
        lambda: store.save(_force(running, tenant_id="tenant-b"), expected_version=a1.state_version),
    )
    registered = running.register_resource(_resource(running, "snapshot", "snap-1"), now=_ts(11))
    _capture(log, "save.register", lambda: store.save(registered, expected_version=running.state_version))
    pending = registered.transition(
        status=ExecutionStatus.SCAN_COMPLETE, phase="cleanup", cleanup_status=CleanupStatus.PENDING, package_count=4, now=_ts(12)
    )
    _capture(log, "save.pending", lambda: store.save(pending, expected_version=registered.state_version))
    a2_partial = a2.transition(cleanup_status=CleanupStatus.IN_PROGRESS, status=ExecutionStatus.FAILED, now=_ts(13))
    _capture(log, "save.a2", lambda: store.save(a2_partial, expected_version=a2.state_version))
    b1_pending = b1.transition(cleanup_status=CleanupStatus.PENDING, now=_ts(14))
    _capture(log, "save.b1", lambda: store.save(b1_pending, expected_version=b1.state_version))

    _capture(log, "recent.a", lambda: [r.execution_id for r in store.list_recent(tenant_id="tenant-a")])
    _capture(log, "recent.b", lambda: [r.execution_id for r in store.list_recent(tenant_id="tenant-b")])
    _capture(log, "recent.none", lambda: store.list_recent(tenant_id="tenant-z"))
    for label, kwargs in (
        ("page.0", {"limit": 2, "offset": 0}),
        ("page.1", {"limit": 2, "offset": 2}),
        ("page.past", {"limit": 2, "offset": 9}),
        ("page.provider", {"limit": 10, "offset": 0, "provider": "azure"}),
        ("page.status", {"limit": 10, "offset": 0, "status": "scan_complete"}),
        ("page.query", {"limit": 10, "offset": 0, "query": "  VM-00 "}),
        ("page.query_account", {"limit": 10, "offset": 0, "query": "sub"}),
        ("page.bad_limit", {"limit": 0, "offset": 0}),
        ("page.bad_offset", {"limit": 1, "offset": -1}),
    ):
        _capture(log, f"{label}.list", lambda k=kwargs: [r.execution_id for r in store.list_page(tenant_id="tenant-a", **k)])
        _capture(
            log,
            f"{label}.with_total",
            lambda k=kwargs: (lambda res: ([r.execution_id for r in res[0]], res[1]))(
                store.list_page_with_total(tenant_id="tenant-a", **k)
            ),
        )
    for label, kwargs in (("all", {}), ("aws", {"provider": "aws"}), ("failed", {"status": "failed"}), ("q", {"query": "i-00"})):
        _capture(log, f"count.{label}", lambda k=kwargs: store.count(tenant_id="tenant-a", **k))
    _capture(log, "count.b", lambda: store.count(tenant_id="tenant-b"))
    _capture(log, "cleanup_due.a", lambda: [r.execution_id for r in store.list_cleanup_due(tenant_id="tenant-a")])
    _capture(log, "cleanup_due.a.limit1", lambda: [r.execution_id for r in store.list_cleanup_due(tenant_id="tenant-a", limit=1)])
    _capture(log, "cleanup_due.b", lambda: [r.execution_id for r in store.list_cleanup_due(tenant_id="tenant-b")])
    _capture(log, "cleanup_due.bad", lambda: store.list_cleanup_due(tenant_id="tenant-a", limit=0))
    _capture(log, "final.a1", lambda: store.get(tenant_id="tenant-a", execution_id=a1.execution_id))
    return log


class _Cursor:
    def __init__(self, rowcount: int, rows: list[tuple[object, ...]]) -> None:
        self.rowcount = rowcount
        self._rows = rows

    def fetchone(self) -> tuple[object, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return list(self._rows)


class _FakePgConnection:
    def __init__(self, calls: list[object], script: list[tuple[int, list[tuple[object, ...]]]]) -> None:
        self._calls = calls
        self._script = script

    def execute(self, sql: str, params: object = None) -> _Cursor:
        rendered = [_param(p) for p in params] if isinstance(params, (list, tuple)) else params
        self._calls.append({"sql": " ".join(str(sql).split()), "params": rendered})
        rowcount, rows = self._script.pop(0) if self._script else (0, [])
        return _Cursor(rowcount, rows)

    def commit(self) -> None:
        self._calls.append("commit")

    def rollback(self) -> None:
        self._calls.append("rollback")


def _param(value: object) -> object:
    if isinstance(value, str) and value.startswith("{"):
        return {"json": json.loads(value)}
    return value


class _FakePool:
    def __init__(self, calls: list[object], script: list[tuple[int, list[tuple[object, ...]]]]) -> None:
        self.calls = calls
        self.script = script

    @contextmanager
    def connection(self) -> Iterator[_FakePgConnection]:
        yield _FakePgConnection(self.calls, self.script)


def _postgres_lifecycle(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    from agent_bom.api import postgres_common

    calls: list[object] = []
    script: list[tuple[int, list[tuple[object, ...]]]] = []

    @contextmanager
    def tenant_connection(pool: _FakePool) -> Iterator[_FakePgConnection]:
        calls.append({"tenant_bound": postgres_common._current_tenant.get()})
        with pool.connection() as conn:
            yield conn

    monkeypatch.setattr(postgres_common, "_tenant_connection", tenant_connection)
    monkeypatch.setattr(postgres_common, "_ensure_tenant_rls", lambda _c, table, col: calls.append({"rls": [table, col]}))
    pool = _FakePool(calls, script)
    log: list[object] = []
    store = _capture(log, "init", lambda: type(PostgresSideScanStateStore(pool=pool)).__name__)
    assert store is not None
    pg = PostgresSideScanStateStore(pool=pool)
    calls.clear()
    a1 = _new("tenant-a", "i-0001", "job-1", n=1)
    running = a1.transition(status=ExecutionStatus.RUNNING, phase="snapshot", now=_ts(10))
    payload = json.dumps(a1.to_dict(), sort_keys=True, separators=(",", ":"))
    run_payload = json.dumps(running.to_dict(), sort_keys=True, separators=(",", ":"))

    def step(label: str, scripted: list[tuple[int, list[tuple[object, ...]]]], fn: Callable[[], object]) -> None:
        script[:] = scripted
        calls.clear()
        _capture(log, label, fn)
        log.append({"op": f"{label}.sql", "calls": list(calls)})

    step("create", [(1, []), (1, [(payload,)])], lambda: pg.create_or_get(a1))
    step("create.lost", [(0, []), (0, [])], lambda: pg.create_or_get(a1))
    step("get.hit", [(1, [(payload,)])], lambda: pg.get(tenant_id="tenant-a", execution_id=a1.execution_id))
    step("get.miss", [(0, [])], lambda: pg.get(tenant_id="tenant-b", execution_id=a1.execution_id))
    step("save.ok", [(1, [])], lambda: pg.save(running, expected_version=1))
    step("save.conflict", [(0, [])], lambda: pg.save(running, expected_version=1))
    step("save.skip", [], lambda: pg.save(running, expected_version=5))
    step("recent", [(1, [(run_payload, 2), (payload, 2)])], lambda: [r.state_version for r in pg.list_recent(tenant_id="tenant-a")])
    step(
        "page.filtered",
        [(1, [(None, 3)])],
        lambda: pg.list_page_with_total(tenant_id="tenant-a", limit=5, offset=10, provider="aws", status="running", query="  I-0 "),
    )
    step("page.empty", [(0, [])], lambda: pg.list_page_with_total(tenant_id="tenant-a", limit=5, offset=0))
    step("page.bad", [], lambda: pg.list_page(tenant_id="tenant-a", limit=0, offset=0))
    step("count", [(1, [(7,)])], lambda: pg.count(tenant_id="tenant-a", provider="gcp", status="failed", query="x"))
    step("count.none", [(0, [])], lambda: pg.count(tenant_id="tenant-a"))
    step("cleanup_due", [(1, [(payload,)])], lambda: [r.execution_id for r in pg.list_cleanup_due(tenant_id="tenant-a", limit=3)])
    step("cleanup_due.bad", [], lambda: pg.list_cleanup_due(tenant_id="tenant-a", limit=0))
    return log


def _factory_lifecycle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[object]:
    from agent_bom.api import postgres_common

    log: list[object] = []
    for var in ("AGENT_BOM_SIDE_SCAN_STATE_DB", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_DB", "AGENT_BOM_EPHEMERAL_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    reset_side_scan_state_store()
    try:
        _capture(log, "explicit_path", lambda: type(get_side_scan_state_store(state_db_path=tmp_path / "x.db")).__name__)
        monkeypatch.setenv("AGENT_BOM_SIDE_SCAN_STATE_DB", str(tmp_path / "env.db"))
        _capture(log, "env_path", lambda: type(get_side_scan_state_store()).__name__)
        _capture(log, "env_path.not_cached", lambda: get_side_scan_state_store() is get_side_scan_state_store())
        monkeypatch.delenv("AGENT_BOM_SIDE_SCAN_STATE_DB")
        first = get_side_scan_state_store()
        _capture(log, "default_sqlite", lambda: type(first).__name__)
        _capture(log, "default_sqlite.file", lambda: (tmp_path / "state" / "side_scan_state.db").is_file())
        _capture(log, "default.cached", lambda: get_side_scan_state_store() is first)
        _capture(log, "default.global", lambda: lifecycle._default_side_scan_store is first)
        reset_side_scan_state_store()
        _capture(log, "reset.global", lambda: lifecycle._default_side_scan_store is None)
        monkeypatch.setenv("AGENT_BOM_EPHEMERAL_STORE", "1")
        mem = get_side_scan_state_store()
        _capture(log, "ephemeral", lambda: type(mem).__name__)
        _capture(log, "ephemeral.cached", lambda: get_side_scan_state_store() is mem)
        reset_side_scan_state_store()
        _capture(log, "ephemeral.reset_new", lambda: get_side_scan_state_store() is not mem)
        reset_side_scan_state_store()
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fake-host/fake")
        monkeypatch.setattr(postgres_common, "_get_pool", lambda: _FakePool([], [(1, [(1,)])]))
        monkeypatch.setattr(postgres_common, "_ensure_tenant_rls", lambda *_a: None)
        _capture(log, "postgres", lambda: type(get_side_scan_state_store()).__name__)
        sentinel = InMemorySideScanStateStore()
        monkeypatch.setattr(lifecycle, "_default_side_scan_store", sentinel)
        _capture(log, "patched_global.honored", lambda: get_side_scan_state_store() is sentinel)
    finally:
        reset_side_scan_state_store()
    return log


def _build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, object]:
    return {
        "model": _model_lifecycle(),
        "store.memory": _store_lifecycle(InMemorySideScanStateStore()),
        "store.sqlite": _store_lifecycle(SQLiteSideScanStateStore(tmp_path / "side_scan.db")),
        "store.sqlite.restart": [
            {"op": "reopen", "result": _render(SQLiteSideScanStateStore(tmp_path / "side_scan.db").list_recent(tenant_id="tenant-a"))}
        ],
        "store.postgres_fake": _postgres_lifecycle(monkeypatch),
        "factory": _factory_lifecycle(monkeypatch, tmp_path),
    }


def test_side_scan_lifecycle_golden(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    actual = json.loads(json.dumps(_build(monkeypatch, tmp_path), sort_keys=True))
    if os.environ.get("UPDATE_CLOUD_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert actual == expected


def test_new_side_scan_execution_patch_on_facade_is_resolved_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    """Callers import ``new_side_scan_execution`` from the façade inside the function body."""

    def fake(**_kwargs: Any) -> SideScanExecutionRecord:
        raise RuntimeError("patched")

    monkeypatch.setattr(lifecycle, "new_side_scan_execution", fake)
    from agent_bom.cloud.side_scan_lifecycle import new_side_scan_execution as resolved

    assert resolved is fake


def test_patched_default_store_global_is_read_by_getter(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AGENT_BOM_SIDE_SCAN_STATE_DB",):
        monkeypatch.delenv(var, raising=False)
    sentinel = InMemorySideScanStateStore()
    monkeypatch.setattr(lifecycle, "_default_side_scan_store", sentinel)
    assert get_side_scan_state_store() is sentinel
    reset_side_scan_state_store()
    assert lifecycle._default_side_scan_store is None


def test_conflict_error_identity_is_shared() -> None:
    store = InMemorySideScanStateStore()
    record = store.create_or_get(_new("tenant-a", "i-1", "k", n=1))
    with pytest.raises(SideScanStateConflictError):
        store.save(record, expected_version=record.state_version)
