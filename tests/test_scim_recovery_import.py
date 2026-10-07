"""Explicit SCIM recovery retains deprovisioning and complete group membership."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.scim_store import SCIMGroup, SCIMUser, SQLiteSCIMStore
from agent_bom.api.storage.registry_import import import_registries, read_source

TABLES = ["scim_users", "scim_groups"]


def seed(path):
    owner = SQLiteSCIMStore(str(path))
    group = owner.put_group(SCIMGroup(tenant_id="source", group_id="group", display_name="Reviewers", members=[{"value": "user"}]))
    user = owner.put_user(SCIMUser(tenant_id="source", user_id="user", user_name="retired@example.invalid", active=False, groups=["group"]))
    return user, group


def test_scim_recovery_requires_complete_read_only_snapshot(tmp_path):
    path = tmp_path / "scim.db"
    user, group = seed(path)
    before = path.read_bytes()
    rows = read_source(path, {"source": "target"}, TABLES)
    restored = next(record for table, record, _ in rows if table == "scim_users")
    assert not restored.active and restored.updated_at == user.updated_at
    assert path.read_bytes() == before
    with pytest.raises(ValueError, match="both SCIM"):
        read_source(path, {"source": "target"}, ["scim_users"])
    group.members = [{"value": "missing"}]
    SQLiteSCIMStore(str(path)).put_group(group)
    with pytest.raises(ValueError, match="membership"):
        read_source(path, {"source": "target"}, TABLES)


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")
def test_scim_recovery_preserves_deactivation_and_refuses_target_identity_merge(tmp_path):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_scim import PostgresSCIMStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    path = tmp_path / "scim.db"
    user, group = seed(path)
    tenant = "restore-" + uuid4().hex
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        assert not import_registries(path, {"source": tenant}, TABLES, pool=pool)["committed"]
        receipt = import_registries(path, {"source": tenant}, TABLES, apply=True, pool=pool)
        assert receipt["committed"] and receipt["inserted"] == 2
        assert import_registries(path, {"source": tenant}, TABLES, apply=True, pool=pool)["unchanged"] == 2
        with tenant_scope(tenant):
            target = PostgresSCIMStore(pool=pool)
            saved = target.get_user(tenant, "user")
            assert not saved.active and saved.updated_at == user.updated_at
            assert target.get_group(tenant, "group").updated_at == group.updated_at
            assert target.list_users(tenant) == []
            target.put_user(SCIMUser(tenant_id=tenant, user_name="another@example.invalid"))
        assert not import_registries(path, {"source": tenant}, TABLES, apply=True, pool=pool)["committed"]
        with tenant_scope("other"):
            assert target.get_user(tenant, "user") is None
    finally:
        pool.close()
