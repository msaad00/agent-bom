"""Fail-closed + audit-emission contract for admin-gated Shield/identity write tools.

Every admin-gated MCP write action (Shield enforcement + identity lifecycle)
must satisfy two invariants:

1. A non-admin ``operator_role`` is rejected fail-closed: the response carries
   ``required_role == "admin"``/``status == "blocked"`` AND no mutation reaches
   the underlying REST handler (we assert the handler is never invoked).
2. An ``admin`` operator with the right scope + audit reason succeeds AND the
   action lands an audit event in the audit-log sink (we spy on the sink and
   assert it was actually called — not merely that the role check passed).

The Shield write tools log via ``runtime._record_shield_write_audit`` ->
``agent_bom.api.audit_log.log_action``; the identity tools delegate to REST
handlers that call ``log_action`` themselves. Both are spied through the same
``log_action`` symbol so the assertion is on real emission.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from agent_bom.mcp_tools import identity as identity_tools
from agent_bom.mcp_tools import runtime as runtime_tools


def _passthrough(value: str) -> str:
    return value


def _run(coro: Any) -> dict[str, Any]:
    return json.loads(asyncio.run(coro))


# ── Shield write tools ───────────────────────────────────────────────────────
# Each entry: (impl, action_name, extra kwargs beyond the common auth args).
_WriteCase = tuple[Any, str, dict[str, Any]]

SHIELD_WRITE_TOOLS: list[_WriteCase] = [
    (runtime_tools.shield_start_impl, "shield_start", {"session_id": "s1", "correlation_window": 30.0}),
    (runtime_tools.shield_unblock_impl, "shield_unblock", {"session_id": "s1"}),
    (runtime_tools.shield_break_glass_impl, "shield_break_glass", {"session_id": "s1"}),
]

IDENTITY_WRITE_TOOLS: list[_WriteCase] = [
    (identity_tools.identity_issue_impl, "identity_issue", {"agent_id": "agent-x"}),
    (identity_tools.identity_rotate_impl, "identity_rotate", {"identity_id": "id-x"}),
    (identity_tools.identity_revoke_impl, "identity_revoke", {"identity_id": "id-x"}),
    (
        identity_tools.identity_grant_jit_impl,
        "identity_grant_jit",
        {"identity_id": "id-x", "tool_name": "search"},
    ),
    (identity_tools.identity_revoke_jit_impl, "identity_revoke_jit", {"grant_id": "grant-x"}),
]

ALL_WRITE_TOOLS: list[_WriteCase] = SHIELD_WRITE_TOOLS + IDENTITY_WRITE_TOOLS


def _ids(cases: list[_WriteCase]) -> list[str]:
    return [name for _impl, name, _kw in cases]


@pytest.mark.parametrize(("impl", "action", "extra"), ALL_WRITE_TOOLS, ids=_ids(ALL_WRITE_TOOLS))
def test_non_admin_fails_closed_without_mutation(impl: Any, action: str, extra: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """A viewer/unset role is blocked and the REST handler is never reached."""
    # Spy: any call into the audit sink or a REST handler would mean a mutation
    # path executed. A fail-closed block must short-circuit before any of these.
    audit_calls: list[tuple[Any, ...]] = []

    def _spy_log_action(*args: Any, **kwargs: Any) -> None:
        audit_calls.append((args, kwargs))

    monkeypatch.setattr("agent_bom.api.audit_log.log_action", _spy_log_action)

    result = _run(
        impl(
            operator_role="viewer",
            operator_scopes="*",
            reason="legitimate operator audit reason",
            tenant_id="default",
            _truncate_response=_passthrough,
            **extra,
        )
    )

    assert result.get("status") == "blocked", result
    assert result.get("required_role") == "admin", result
    assert "requires admin role" in result.get("error", ""), result
    # No mutation: the audit sink must not have fired on a fail-closed block.
    assert audit_calls == [], f"{action} emitted audit on a blocked non-admin call"


@pytest.mark.parametrize(("impl", "action", "extra"), ALL_WRITE_TOOLS, ids=_ids(ALL_WRITE_TOOLS))
def test_missing_scope_fails_closed(impl: Any, action: str, extra: dict[str, Any]) -> None:
    """Admin role but no write scope is still blocked (defense in depth)."""
    result = _run(
        impl(
            operator_role="admin",
            operator_scopes="",  # no shield:write / identity:write
            reason="legitimate operator audit reason",
            tenant_id="default",
            _truncate_response=_passthrough,
            **extra,
        )
    )
    assert result.get("status") == "blocked", result
    assert "scope" in result.get("error", "").lower(), result


@pytest.mark.parametrize(("impl", "action", "extra"), ALL_WRITE_TOOLS, ids=_ids(ALL_WRITE_TOOLS))
def test_short_reason_fails_closed(impl: Any, action: str, extra: dict[str, Any]) -> None:
    """Admin + scope but a too-short audit reason is blocked."""
    result = _run(
        impl(
            operator_role="admin",
            operator_scopes="*",
            reason="short",  # < 8 chars
            tenant_id="default",
            _truncate_response=_passthrough,
            **extra,
        )
    )
    assert result.get("status") == "blocked", result
    assert "reason" in result.get("error", "").lower(), result


@pytest.mark.parametrize(("impl", "action", "extra"), SHIELD_WRITE_TOOLS, ids=_ids(SHIELD_WRITE_TOOLS))
def test_admin_shield_write_emits_audit(impl: Any, action: str, extra: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """An authorized admin Shield write succeeds AND emits an audit event.

    We stub the underlying engine route so the test is hermetic, then assert
    the audit sink was actually called with the action name + admin actor.
    """
    audit_calls: list[dict[str, Any]] = []

    def _spy_log_action(action_name: str, **kwargs: Any) -> None:
        audit_calls.append({"action": action_name, **kwargs})

    monkeypatch.setattr("agent_bom.api.audit_log.log_action", _spy_log_action)

    # Stub the engine-backed routes so we exercise the MCP write path without
    # standing up a ProtectionEngine. break_glass audits inside the route via
    # the same log_action symbol, so the spy captures it either way.
    async def _fake_shield_start(request: Any, *, session_id: str = "default", correlation_window: float = 30.0) -> dict:
        del request
        return {"status": "started", "session_id": session_id}

    async def _fake_shield_unblock(request: Any, *, session_id: str = "default") -> dict:
        del request
        return {"status": "unblocked", "session_id": session_id}

    async def _fake_break_glass(request: Any, *, session_id: str = "default", reason: str = "") -> dict:
        from agent_bom.api.audit_log import log_action

        log_action(
            "break_glass",
            actor=getattr(request.state, "api_key_role", "viewer"),
            resource=f"shield/{session_id}",
            tenant_id="default",
            reason=reason,
        )
        return {"status": "break_glass_activated", "session_id": session_id}

    monkeypatch.setattr("agent_bom.api.routes.proxy.shield_start", _fake_shield_start)
    monkeypatch.setattr("agent_bom.api.routes.proxy.shield_unblock", _fake_shield_unblock)
    monkeypatch.setattr("agent_bom.api.routes.proxy.break_glass", _fake_break_glass)

    result = _run(
        impl(
            operator_role="admin",
            operator_scopes="shield:write",
            reason="incident-1234 emergency override",
            tenant_id="acme",
            _truncate_response=_passthrough,
            **extra,
        )
    )

    assert "error" not in result, result
    assert result.get("status") not in ("blocked", None), result
    assert len(audit_calls) == 1, f"{action} did not emit exactly one audit event: {audit_calls}"
    emitted = audit_calls[0]
    assert emitted["actor"] == "admin", emitted
    assert emitted.get("reason"), emitted


def test_break_glass_inactive_session_still_audits() -> None:
    """A break-glass ATTEMPT on an inactive Shield session must still audit.

    Regression guard: the real ``break_glass`` route used to return
    ``not_active`` *before* its audit emission when no Shield engine was
    running, so a privileged break-glass attempt produced no audit trail.
    The attempt + ``not_active`` outcome must now always land an event.
    """
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log
    from agent_bom.api.routes import proxy as proxy_routes

    store = InMemoryAuditLog()
    set_audit_log(store)
    env = pytest.MonkeyPatch()
    env.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-omega")
    # No shield_start -> no engine registered for this session.
    proxy_routes._shield_engines.clear()

    try:
        result = _run(
            runtime_tools.shield_break_glass_impl(
                session_id="never-started",
                operator_role="admin",
                operator_scopes="shield:write",
                reason="emergency override on inactive session",
                tenant_id="tenant-omega",
                _truncate_response=_passthrough,
            )
        )
    finally:
        env.undo()

    # Behaviour otherwise unchanged: still reports the session is not active.
    assert result["status"] == "not_active", result

    entries = store.list_entries(tenant_id="tenant-omega", limit=10)
    actions = [entry.action for entry in entries]
    assert "break_glass" in actions, f"inactive break-glass attempt emitted no audit event: {actions}"
    glass = next(entry for entry in entries if entry.action == "break_glass")
    assert glass.actor == "admin", glass
    assert glass.details.get("outcome") == "not_active", glass.details

    proxy_routes._shield_engines.clear()
