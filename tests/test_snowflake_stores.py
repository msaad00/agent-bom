"""Tests for Snowflake-backed storage backends.

All Snowflake connector calls are mocked — no real Snowflake account needed.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _mock_cursor(fetchone_val=None, fetchall_val=None, rowcount=0):
    cur = MagicMock()
    cur.fetchone.return_value = fetchone_val
    cur.fetchall.return_value = fetchall_val or []
    cur.rowcount = rowcount
    cur.execute.return_value = cur
    return cur


def _mock_connection(cursor=None):
    conn = MagicMock()
    conn.cursor.return_value = cursor or _mock_cursor()
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return conn


SF_PARAMS = {
    "account": "test_account",
    "user": "test_user",
    "password": "test_pass",
    "database": "AGENT_BOM",
    "schema": "PUBLIC",
}


# ─── build_connection_params ──────────────────────────────────────────────────


class TestBuildConnectionParams:
    def test_password_auth_deprecated(self, monkeypatch):
        """SNOWFLAKE_PASSWORD still works but emits DeprecationWarning."""
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
        monkeypatch.setenv("SNOWFLAKE_USER", "usr1")
        monkeypatch.setenv("SNOWFLAKE_PASSWORD", "pw1")
        monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PATH", raising=False)

        import warnings

        from agent_bom.api.snowflake_store import build_connection_params

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            p = build_connection_params()
            assert p["account"] == "acct1"
            assert p["user"] == "usr1"
            assert p["password"] == "pw1"
            assert "private_key_file" not in p
            assert any(issubclass(x.category, DeprecationWarning) for x in w)

    def test_sso_default(self, monkeypatch):
        """When no key-pair or password is set, defaults to SSO."""
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct_sso")
        monkeypatch.setenv("SNOWFLAKE_USER", "usr_sso")
        monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PATH", raising=False)
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)

        from agent_bom.api.snowflake_store import build_connection_params

        p = build_connection_params()
        assert p["authenticator"] == "externalbrowser"
        assert "password" not in p

    def test_keypair_auth(self, monkeypatch):
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct2")
        monkeypatch.setenv("SNOWFLAKE_USER", "usr2")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "secret")
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)

        from agent_bom.api.snowflake_store import build_connection_params

        p = build_connection_params()
        assert p["private_key_file"] == "/keys/rsa.p8"
        assert p["private_key_file_pwd"] == "secret"
        assert "password" not in p

    def test_keypair_no_passphrase(self, monkeypatch):
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct3")
        monkeypatch.setenv("SNOWFLAKE_USER", "usr3")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
        monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)

        from agent_bom.api.snowflake_store import build_connection_params

        p = build_connection_params()
        assert p["private_key_file"] == "/keys/rsa.p8"
        assert "private_key_file_pwd" not in p

    def test_custom_database_schema(self, monkeypatch):
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct4")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
        monkeypatch.setenv("SNOWFLAKE_DATABASE", "MY_DB")
        monkeypatch.setenv("SNOWFLAKE_SCHEMA", "MY_SCHEMA")
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)

        from agent_bom.api.snowflake_store import build_connection_params

        p = build_connection_params()
        assert p["database"] == "MY_DB"
        assert p["schema"] == "MY_SCHEMA"


# ─── _resolve_snowflake_auth ─────────────────────────────────────────────────


class TestResolveSnowflakeAuth:
    def test_explicit_authenticator(self, monkeypatch):
        monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)
        from agent_bom.cloud.snowflake import _resolve_snowflake_auth

        kwargs: dict = {}
        _resolve_snowflake_auth(kwargs, "oauth")
        assert kwargs["authenticator"] == "oauth"
        assert "password" not in kwargs

    def test_env_authenticator(self, monkeypatch):
        monkeypatch.setenv("SNOWFLAKE_AUTHENTICATOR", "snowflake_jwt")
        from agent_bom.cloud.snowflake import _resolve_snowflake_auth

        kwargs: dict = {}
        _resolve_snowflake_auth(kwargs, None)
        assert kwargs["authenticator"] == "snowflake_jwt"

    def test_keypair_auth(self, monkeypatch):
        monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "secret")
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
        from agent_bom.cloud.snowflake import _resolve_snowflake_auth

        kwargs: dict = {}
        _resolve_snowflake_auth(kwargs, None)
        assert kwargs["private_key_file"] == "/keys/rsa.p8"
        assert kwargs["private_key_file_pwd"] == "secret"
        assert "password" not in kwargs
        assert "authenticator" not in kwargs

    def test_keypair_no_passphrase(self, monkeypatch):
        monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
        monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", raising=False)
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
        from agent_bom.cloud.snowflake import _resolve_snowflake_auth

        kwargs: dict = {}
        _resolve_snowflake_auth(kwargs, None)
        assert kwargs["private_key_file"] == "/keys/rsa.p8"
        assert "private_key_file_pwd" not in kwargs

    def test_password_deprecated(self, monkeypatch):
        import warnings

        monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)
        monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PATH", raising=False)
        monkeypatch.setenv("SNOWFLAKE_PASSWORD", "legacy-pw")
        from agent_bom.cloud.snowflake import _resolve_snowflake_auth

        kwargs: dict = {}
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            _resolve_snowflake_auth(kwargs, None)
            assert kwargs["password"] == "legacy-pw"
            assert any(issubclass(x.category, DeprecationWarning) for x in w)
            assert any("SNOWFLAKE_PASSWORD is deprecated" in str(x.message) for x in w)

    def test_sso_default(self, monkeypatch):
        monkeypatch.delenv("SNOWFLAKE_AUTHENTICATOR", raising=False)
        monkeypatch.delenv("SNOWFLAKE_PRIVATE_KEY_PATH", raising=False)
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
        from agent_bom.cloud.snowflake import _resolve_snowflake_auth

        kwargs: dict = {}
        _resolve_snowflake_auth(kwargs, None)
        assert kwargs["authenticator"] == "externalbrowser"
        assert "password" not in kwargs


# ─── SnowflakeJobStore ───────────────────────────────────────────────────────


class TestSnowflakeJobStore:
    @patch("agent_bom.api.snowflake_store._sf_connect")
    def _make_store(self, mock_connect):
        mock_connect.return_value = _mock_connection()
        from agent_bom.api.snowflake_store import SnowflakeJobStore

        return SnowflakeJobStore(SF_PARAMS)

    def _make_job(self, job_id="j1", status="pending"):
        from agent_bom.api.server import JobStatus, ScanJob, ScanRequest

        return ScanJob(
            job_id=job_id,
            status=JobStatus(status),
            created_at=datetime.now(timezone.utc).isoformat(),
            request=ScanRequest(),
        )

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_init_creates_table(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        from agent_bom.api.snowflake_store import SnowflakeJobStore

        SnowflakeJobStore(SF_PARAMS)
        create_call = conn.cursor().execute.call_args_list[0]
        assert "CREATE TABLE IF NOT EXISTS scan_jobs" in create_call[0][0]

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_put(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        job = self._make_job()
        store.put(job)
        calls = conn.cursor().execute.call_args_list
        merge_call = [c for c in calls if "MERGE INTO scan_jobs" in str(c)]
        assert len(merge_call) > 0

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_found(self, mock_connect):
        job = self._make_job()
        job_json = job.model_dump_json()
        cur = _mock_cursor(fetchone_val=(job_json,))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get("j1", tenant_id="default")
        assert result is not None
        assert result.job_id == "j1"
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "WHERE job_id = %s AND tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_not_found(self, mock_connect):
        cur = _mock_cursor(fetchone_val=None)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.get("missing") is None

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_variant_dict(self, mock_connect):
        """Snowflake may return VARIANT as dict instead of string."""
        job = self._make_job()
        job_dict = json.loads(job.model_dump_json())
        cur = _mock_cursor(fetchone_val=(job_dict,))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get("j1")
        assert result is not None
        assert result.job_id == "j1"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete_found(self, mock_connect):
        cur = _mock_cursor(rowcount=1)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete("j1", tenant_id="default") is True
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "DELETE FROM scan_jobs WHERE job_id = %s AND tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete_not_found(self, mock_connect):
        cur = _mock_cursor(rowcount=0)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete("missing") is False

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_all(self, mock_connect):
        j1 = self._make_job("j1")
        j2 = self._make_job("j2")
        cur = _mock_cursor(fetchall_val=[(j1.model_dump_json(),), (j2.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_all()
        assert len(result) == 2

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_summary(self, mock_connect):
        cur = _mock_cursor(fetchall_val=[("j1", "tenant-alpha", "done", "2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z")])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_summary()
        assert len(result) == 1
        assert result[0]["job_id"] == "j1"
        assert result[0]["tenant_id"] == "tenant-alpha"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_cleanup_expired(self, mock_connect):
        cur = _mock_cursor(rowcount=3)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        count = store.cleanup_expired(ttl_seconds=60)
        assert count == 3


# ─── SnowflakeFleetStore ─────────────────────────────────────────────────────


class TestSnowflakeFleetStore:
    @patch("agent_bom.api.snowflake_store._sf_connect")
    def _make_store(self, mock_connect):
        mock_connect.return_value = _mock_connection()
        from agent_bom.api.snowflake_store import SnowflakeFleetStore

        return SnowflakeFleetStore(SF_PARAMS)

    def _make_agent(self, agent_id="a1", name="test-agent"):
        from agent_bom.api.fleet_store import FleetAgent

        return FleetAgent(
            agent_id=agent_id,
            name=name,
            agent_type="claude_desktop",
            tenant_id="tenant-alpha",
            updated_at=datetime.now(timezone.utc).isoformat(),
        )

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_init_creates_table(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        from agent_bom.api.snowflake_store import SnowflakeFleetStore

        SnowflakeFleetStore(SF_PARAMS)
        calls = [str(c) for c in conn.cursor().execute.call_args_list]
        assert any("CREATE TABLE IF NOT EXISTS fleet_agents" in c and "tenant_id VARCHAR NOT NULL DEFAULT 'default'" in c for c in calls)
        assert any("ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS tenant_id" in c for c in calls)

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_put(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        agent = self._make_agent()
        store.put(agent)
        calls = conn.cursor().execute.call_args_list
        merge_call = [c for c in calls if "MERGE INTO fleet_agents" in str(c)]
        assert len(merge_call) > 0
        assert any(agent.tenant_id in str(c) for c in merge_call)

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_found(self, mock_connect):
        agent = self._make_agent()
        cur = _mock_cursor(fetchone_val=(agent.model_dump_json(),))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get("a1", tenant_id="tenant-alpha")
        assert result is not None
        assert result.agent_id == "a1"
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "WHERE agent_id = %s AND tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_not_found(self, mock_connect):
        cur = _mock_cursor(fetchone_val=None)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.get("missing") is None

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_by_name(self, mock_connect):
        agent = self._make_agent()
        cur = _mock_cursor(fetchone_val=(agent.model_dump_json(),))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get_by_name("test-agent")
        assert result is not None
        assert result.name == "test-agent"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete(self, mock_connect):
        cur = _mock_cursor(rowcount=1)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete("a1", tenant_id="tenant-alpha") is True
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "DELETE FROM fleet_agents WHERE agent_id = %s AND tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_all(self, mock_connect):
        a1 = self._make_agent("a1", "agent-a")
        a2 = self._make_agent("a2", "agent-b")
        cur = _mock_cursor(fetchall_val=[(a1.model_dump_json(),), (a2.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_all()
        assert len(result) == 2

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_summary(self, mock_connect):
        cur = _mock_cursor(
            fetchall_val=[
                ("a1", "agent-a", "discovered", 0.8, "2025-01-01T00:00:00Z"),
            ]
        )
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_summary()
        assert len(result) == 1
        assert result[0]["agent_id"] == "a1"
        assert result[0]["trust_score"] == 0.8

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_by_tenant(self, mock_connect):
        agent = self._make_agent()
        cur = _mock_cursor(fetchall_val=[(agent.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_by_tenant("tenant-alpha")
        assert len(result) == 1
        assert result[0].tenant_id == "tenant-alpha"
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "WHERE tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_tenants(self, mock_connect):
        cur = _mock_cursor(fetchall_val=[("tenant-alpha", 2), ("tenant-beta", 1)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_tenants()
        assert result == [
            {"tenant_id": "tenant-alpha", "agent_count": 2},
            {"tenant_id": "tenant-beta", "agent_count": 1},
        ]

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_update_state_found(self, mock_connect):
        from agent_bom.api.fleet_store import FleetLifecycleState

        agent = self._make_agent()
        cur = _mock_cursor(fetchone_val=(agent.model_dump_json(),))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.update_state("a1", FleetLifecycleState.APPROVED) is True

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_update_state_not_found(self, mock_connect):
        from agent_bom.api.fleet_store import FleetLifecycleState

        cur = _mock_cursor(fetchone_val=None)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.update_state("missing", FleetLifecycleState.APPROVED) is False


# ─── SnowflakePolicyStore ────────────────────────────────────────────────────


class TestSnowflakePolicyStore:
    @patch("agent_bom.api.snowflake_store._sf_connect")
    def _make_store(self, mock_connect):
        mock_connect.return_value = _mock_connection()
        from agent_bom.api.snowflake_store import SnowflakePolicyStore

        return SnowflakePolicyStore(SF_PARAMS)

    def _make_policy(self, policy_id="p1", name="block-danger"):
        from agent_bom.api.policy_store import GatewayPolicy

        return GatewayPolicy(
            policy_id=policy_id,
            name=name,
            updated_at=datetime.now(timezone.utc).isoformat(),
            tenant_id="tenant-alpha",
        )

    def _make_audit_entry(self, entry_id="e1"):
        from agent_bom.api.policy_store import PolicyAuditEntry

        return PolicyAuditEntry(
            entry_id=entry_id,
            policy_id="p1",
            policy_name="block-danger",
            rule_id="r1",
            agent_name="test-agent",
            tool_name="exec_sql",
            action_taken="blocked",
            reason="matched rule",
            timestamp=datetime.now(timezone.utc).isoformat(),
            tenant_id="tenant-alpha",
        )

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_init_creates_tables(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        from agent_bom.api.snowflake_store import SnowflakePolicyStore

        SnowflakePolicyStore(SF_PARAMS)
        calls = [str(c) for c in conn.cursor().execute.call_args_list]
        assert any("gateway_policies" in c for c in calls)
        assert any("policy_audit_log" in c for c in calls)

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_put_policy(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        policy = self._make_policy()
        store.put_policy(policy)
        calls = conn.cursor().execute.call_args_list
        merge_call = [c for c in calls if "MERGE INTO gateway_policies" in str(c)]
        assert len(merge_call) > 0

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_policy_found(self, mock_connect):
        policy = self._make_policy()
        cur = _mock_cursor(fetchone_val=(policy.model_dump_json(),))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get_policy("p1")
        assert result is not None
        assert result.policy_id == "p1"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_policy_not_found(self, mock_connect):
        cur = _mock_cursor(fetchone_val=None)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.get_policy("missing") is None

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete_policy(self, mock_connect):
        cur = _mock_cursor(rowcount=1)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete_policy("p1") is True

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete_policy_is_tenant_scoped(self, mock_connect):
        policy = self._make_policy()
        cur = _mock_cursor(fetchone_val=(policy.model_dump_json(),), rowcount=1)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete_policy("p1", tenant_id="default") is True
        delete_call = str(conn.cursor().execute.call_args_list[-1])
        assert "DELETE FROM gateway_policies WHERE policy_id = %s AND tenant_id = %s" in delete_call

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_policies(self, mock_connect):
        p1 = self._make_policy("p1", "a-policy")
        p2 = self._make_policy("p2", "b-policy")
        cur = _mock_cursor(fetchall_val=[(p1.model_dump_json(),), (p2.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_policies()
        assert len(result) == 2

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_policies_tenant_filter_is_pushed_into_sql(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        store.list_policies(tenant_id="tenant-alpha")
        sql_calls = [str(c) for c in conn.cursor().execute.call_args_list if "gateway_policies" in str(c) and "SELECT" in str(c)]
        assert any("tenant_id = %s" in call for call in sql_calls)

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_policies_for_agent_filters(self, mock_connect):
        from agent_bom.api.policy_store import GatewayPolicy

        p1 = GatewayPolicy(
            policy_id="p1",
            name="agent-specific",
            bound_agents=["agent-a"],
            enabled=True,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        p2 = GatewayPolicy(
            policy_id="p2",
            name="global",
            enabled=True,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        cur = _mock_cursor(
            fetchall_val=[
                (p1.model_dump_json(),),
                (p2.model_dump_json(),),
            ]
        )
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get_policies_for_agent(agent_name="agent-b")
        # p1 is bound to agent-a only, so agent-b should only get p2
        assert len(result) == 1
        assert result[0].policy_id == "p2"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_put_audit_entry(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        entry = self._make_audit_entry()
        store.put_audit_entry(entry)
        calls = conn.cursor().execute.call_args_list
        insert_call = [c for c in calls if "INSERT INTO policy_audit_log" in str(c)]
        assert len(insert_call) > 0

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_audit_entries(self, mock_connect):
        e1 = self._make_audit_entry("e1")
        cur = _mock_cursor(fetchall_val=[(e1.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_audit_entries(policy_id="p1")
        assert len(result) == 1
        assert result[0].entry_id == "e1"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_audit_entries_with_filters(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        store.list_audit_entries(policy_id="p1", agent_name="test-agent", tenant_id="tenant-alpha", limit=50)
        calls = conn.cursor().execute.call_args_list
        # Check that the SQL includes both filter clauses
        sql_calls = [str(c) for c in calls if "policy_audit_log" in str(c) and "SELECT" in str(c)]
        assert len(sql_calls) > 0
        assert any("tenant_id = %s" in call for call in sql_calls)


# ─── SnowflakeScheduleStore ──────────────────────────────────────────────────


class TestSnowflakeScheduleStore:
    @patch("agent_bom.api.snowflake_store._sf_connect")
    def _make_store(self, mock_connect):
        mock_connect.return_value = _mock_connection()
        from agent_bom.api.snowflake_store import SnowflakeScheduleStore

        return SnowflakeScheduleStore(SF_PARAMS)

    def _make_schedule(self, schedule_id="sched-1", tenant_id="default", enabled=True, next_run="2025-01-01T00:00:00Z"):
        from agent_bom.api.schedule_store import ScanSchedule

        return ScanSchedule(
            schedule_id=schedule_id,
            name="nightly-scan",
            cron_expression="0 */6 * * *",
            scan_config={"images": ["nginx:latest"]},
            enabled=enabled,
            next_run=next_run,
            created_at="2025-01-01T00:00:00Z",
            updated_at="2025-01-01T00:00:00Z",
            tenant_id=tenant_id,
        )

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_init_creates_table(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        from agent_bom.api.snowflake_store import SnowflakeScheduleStore

        SnowflakeScheduleStore(SF_PARAMS)
        create_call = conn.cursor().execute.call_args_list[0]
        assert "CREATE TABLE IF NOT EXISTS scan_schedules" in create_call[0][0]

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_put(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        store.put(self._make_schedule())
        calls = conn.cursor().execute.call_args_list
        merge_call = [c for c in calls if "MERGE INTO scan_schedules" in str(c)]
        assert len(merge_call) > 0

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_found(self, mock_connect):
        schedule = self._make_schedule()
        cur = _mock_cursor(fetchone_val=(schedule.model_dump_json(),))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get("sched-1", tenant_id="default")
        assert result is not None
        assert result.schedule_id == "sched-1"
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "WHERE schedule_id = %s AND tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_all_tenant_filtered(self, mock_connect):
        s1 = self._make_schedule("sched-1", tenant_id="tenant-a")
        s2 = self._make_schedule("sched-2", tenant_id="tenant-a")
        cur = _mock_cursor(fetchall_val=[(s1.model_dump_json(),), (s2.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_all(tenant_id="tenant-a")
        assert len(result) == 2
        assert all(item.tenant_id == "tenant-a" for item in result)

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_due(self, mock_connect):
        schedule = self._make_schedule("sched-due", enabled=True, next_run="2025-01-01T00:00:00Z")
        cur = _mock_cursor(fetchall_val=[(schedule.model_dump_json(),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_due("2025-06-01T00:00:00Z")
        assert len(result) == 1
        assert result[0].schedule_id == "sched-due"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete_found(self, mock_connect):
        cur = _mock_cursor(rowcount=1)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete("sched-1", tenant_id="default") is True
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "DELETE FROM scan_schedules WHERE schedule_id = %s AND tenant_id = %s" in sql


# ─── SnowflakeExceptionStore ─────────────────────────────────────────────────


class TestSnowflakeExceptionStore:
    @patch("agent_bom.api.snowflake_store._sf_connect")
    def _make_store(self, mock_connect):
        mock_connect.return_value = _mock_connection()
        from agent_bom.api.snowflake_store import SnowflakeExceptionStore

        return SnowflakeExceptionStore(SF_PARAMS)

    def _make_exception(self, exception_id="exc-1", tenant_id="default", status="pending"):
        from agent_bom.api.exception_store import ExceptionStatus, VulnException

        return VulnException(
            exception_id=exception_id,
            vuln_id="CVE-2026-0001",
            package_name="express",
            server_name="filesystem",
            reason="accepted temporary risk",
            requested_by="alice@example.com",
            approved_by="bob@example.com" if status != "pending" else "",
            status=ExceptionStatus(status),
            created_at="2026-01-01T00:00:00Z",
            expires_at="2026-06-01T00:00:00Z",
            tenant_id=tenant_id,
        )

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_init_creates_table(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        from agent_bom.api.snowflake_store import SnowflakeExceptionStore

        SnowflakeExceptionStore(SF_PARAMS)
        create_call = conn.cursor().execute.call_args_list[0]
        assert "CREATE TABLE IF NOT EXISTS exceptions" in create_call[0][0]

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_put(self, mock_connect):
        conn = _mock_connection()
        mock_connect.return_value = conn
        store = self._make_store()
        store.put(self._make_exception())
        calls = conn.cursor().execute.call_args_list
        merge_call = [c for c in calls if "MERGE INTO exceptions" in str(c)]
        assert len(merge_call) > 0

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_get_found(self, mock_connect):
        exc = self._make_exception()
        cur = _mock_cursor(fetchone_val=(json.dumps(exc.to_dict()),))
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.get("exc-1", tenant_id="default")
        assert result is not None
        assert result.exception_id == "exc-1"
        assert result.tenant_id == "default"
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "WHERE exception_id = %s AND tenant_id = %s" in sql

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_list_all_tenant_filtered(self, mock_connect):
        exc = self._make_exception("exc-1", tenant_id="tenant-a", status="approved")
        cur = _mock_cursor(fetchall_val=[(json.dumps(exc.to_dict()),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.list_all(status="approved", tenant_id="tenant-a")
        assert len(result) == 1
        assert result[0].tenant_id == "tenant-a"
        assert result[0].status.value == "approved"

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_find_matching_uses_approved_and_active(self, mock_connect):
        approved = self._make_exception("exc-approved", tenant_id="tenant-a", status="approved")
        active = self._make_exception("exc-active", tenant_id="tenant-a", status="active")
        cur = _mock_cursor(fetchall_val=[(json.dumps(approved.to_dict()),), (json.dumps(active.to_dict()),)])
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        result = store.find_matching("CVE-2026-0001", "express", "filesystem", tenant_id="tenant-a")
        assert result is not None
        assert result.exception_id in {"exc-approved", "exc-active"}

    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_delete_found(self, mock_connect):
        cur = _mock_cursor(rowcount=1)
        conn = _mock_connection(cursor=cur)
        mock_connect.return_value = conn
        store = self._make_store()
        assert store.delete("exc-1", tenant_id="default") is True
        sql = str(conn.cursor().execute.call_args_list[-1])
        assert "DELETE FROM exceptions WHERE exception_id = %s AND tenant_id = %s" in sql


# ─── Server lifespan auto-detection ──────────────────────────────────────────


class TestServerLifespanAutoDetect:
    @patch("agent_bom.api.snowflake_store._sf_connect")
    def test_snowflake_takes_priority(self, mock_sf_connect, monkeypatch):
        """When SNOWFLAKE_ACCOUNT is set, Snowflake stores are used over SQLite."""
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "test_acct")
        monkeypatch.setenv("SNOWFLAKE_USER", "test_user")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/rsa.p8")
        monkeypatch.setenv("AGENT_BOM_DB", "/tmp/should_not_use.db")
        monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)

        mock_sf_connect.return_value = _mock_connection()

        import agent_bom.api.server as srv
        import agent_bom.api.stores as st

        # Reset global stores
        st._store = None
        st._fleet_store = None
        st._policy_store = None
        st._schedule_store = None
        st._exception_store = None

        import asyncio

        async def _run():
            async with srv._lifespan(srv.app):
                pass

        asyncio.run(_run())

        from agent_bom.api.snowflake_store import (
            SnowflakeExceptionStore,
            SnowflakeFleetStore,
            SnowflakeJobStore,
            SnowflakePolicyStore,
            SnowflakeScheduleStore,
        )

        assert isinstance(st._store, SnowflakeJobStore)
        assert isinstance(st._fleet_store, SnowflakeFleetStore)
        assert isinstance(st._policy_store, SnowflakePolicyStore)
        assert isinstance(st._schedule_store, SnowflakeScheduleStore)
        assert isinstance(st._exception_store, SnowflakeExceptionStore)

        # Cleanup
        st._store = None
        st._fleet_store = None
        st._policy_store = None
        st._schedule_store = None
        st._exception_store = None
