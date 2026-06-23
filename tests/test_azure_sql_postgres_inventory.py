"""Managed SQL / PostgreSQL / MySQL servers extend the databases collection."""

from __future__ import annotations

from types import SimpleNamespace as Server

from agent_bom.cloud import azure_inventory as azinv
from agent_bom.cloud.resource_model import CloudResourceType, normalize_cloud_inventory


def test_append_db_servers_reads_both_public_access_shapes() -> None:
    dbs: list[dict] = []
    sql = [
        Server(id="/s/Microsoft.Sql/servers/sql1", name="sql1", location="eastus", tags={}, public_network_access="Enabled", network=None)
    ]
    pg = [
        Server(
            id="/s/flexibleServers/pg1",
            name="pg1",
            location="eastus",
            tags={},
            public_network_access=None,
            network=Server(public_network_access="Disabled"),
        )
    ]
    azinv._append_db_servers(dbs, sql, native_type="Microsoft.Sql/servers", engine="azure-sql")
    azinv._append_db_servers(dbs, pg, native_type="Microsoft.DBforPostgreSQL/flexibleServers", engine="postgresql")
    assert dbs[0]["public_network_access"] == "Enabled"  # direct attr (Azure SQL)
    assert dbs[1]["public_network_access"] == "Disabled"  # via server.network (flexible)
    assert dbs[0]["engine"] == "azure-sql"
    assert dbs[1]["native_type"] == "Microsoft.DBforPostgreSQL/flexibleServers"


def test_sql_family_normalizes_to_database_with_engine_native_type() -> None:
    dbs = [
        {"name": "sql1", "id": "/s/sql1", "native_type": "Microsoft.Sql/servers", "engine": "azure-sql"},
        {"name": "pg1", "id": "/s/pg1", "native_type": "Microsoft.DBforPostgreSQL/flexibleServers", "engine": "postgresql"},
        {"name": "my1", "id": "/s/my1", "native_type": "Microsoft.DBforMySQL/flexibleServers", "engine": "mysql"},
    ]
    inv = {"provider": "azure", "subscription_id": "s", "databases": dbs}
    by_name = {r.name: r for r in normalize_cloud_inventory(inv)}
    assert all(r.resource_type is CloudResourceType.DATABASE for r in by_name.values())
    assert by_name["sql1"].native_type == "Microsoft.Sql/servers"
    assert by_name["pg1"].native_type == "Microsoft.DBforPostgreSQL/flexibleServers"
    assert by_name["my1"].native_type == "Microsoft.DBforMySQL/flexibleServers"


def test_blank_named_server_skipped() -> None:
    dbs: list[dict] = []
    azinv._append_db_servers(dbs, [Server(id="x", name="  ", location="", tags={}, network=None)], native_type="t", engine="e")
    assert dbs == []
