"""Iceberg REST-catalog registration contract for data-lake interop (#3499)."""

from __future__ import annotations

import pytest

from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output import iceberg_catalog
from agent_bom.output.iceberg_catalog import (
    DEFAULT_NAMESPACE,
    DEFAULT_TABLE,
    IcebergCatalogConfig,
    maybe_register_iceberg,
    register_findings,
)

pytest.importorskip("pyarrow")

_ICEBERG_ENV = (
    "AGENT_BOM_ICEBERG_CATALOG_URL",
    "AGENT_BOM_ICEBERG_NAMESPACE",
    "AGENT_BOM_ICEBERG_TABLE",
    "AGENT_BOM_ICEBERG_CREDENTIAL",
    "AGENT_BOM_ICEBERG_TOKEN",
    "AGENT_BOM_ICEBERG_WAREHOUSE",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ICEBERG_ENV:
        monkeypatch.delenv(var, raising=False)


def _report() -> tuple[AIBOMReport, BlastRadius]:
    vuln = Vulnerability(id="CVE-2099-8", summary="x", severity=Severity.HIGH)
    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=["agent-a"],
        exposed_credentials=[],
        exposed_tools=[],
        graph_reachable=True,
        graph_min_hop_distance=1,
    )
    return AIBOMReport(agents=[], blast_radii=[br], scan_id="iceberg-test"), br


class _FakeSnapshot:
    snapshot_id = 4242


class _FakeTable:
    def __init__(self, identifier, schema):
        self.identifier = identifier
        self.schema = schema
        self.appended = []

    def append(self, arrow_table):
        self.appended.append(arrow_table)

    def current_snapshot(self):
        return _FakeSnapshot()


class _FakeCatalog:
    """In-memory stand-in for pyiceberg RestCatalog (no network)."""

    def __init__(self):
        self.namespaces: list[tuple] = []
        self.tables: dict[str, _FakeTable] = {}

    def create_namespace_if_not_exists(self, namespace):
        self.namespaces.append(namespace)

    def create_table_if_not_exists(self, identifier, schema):
        table = self.tables.get(identifier)
        if table is None:
            table = _FakeTable(identifier, schema)
            self.tables[identifier] = table
        return table


# ── config / request construction ────────────────────────────────────────────


def test_config_disabled_by_default() -> None:
    assert IcebergCatalogConfig().enabled is False
    assert IcebergCatalogConfig(catalog_url="http://cat/").enabled is True


def test_config_from_env(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_ICEBERG_CATALOG_URL", "http://catalog:8181")
    monkeypatch.setenv("AGENT_BOM_ICEBERG_NAMESPACE", "lake")
    monkeypatch.setenv("AGENT_BOM_ICEBERG_TABLE", "cves")
    monkeypatch.setenv("AGENT_BOM_ICEBERG_TOKEN", "tok123")

    config = IcebergCatalogConfig.from_env()
    assert config.enabled is True
    assert config.identifier == "lake.cves"
    props = config.catalog_properties()
    assert props == {"uri": "http://catalog:8181", "token": "tok123"}


def test_config_defaults_and_explicit_args_win() -> None:
    config = IcebergCatalogConfig.from_env(catalog_url="http://c/", namespace="ns")
    assert config.namespace == "ns"
    assert config.table == DEFAULT_TABLE
    assert config.namespace != DEFAULT_NAMESPACE


def test_catalog_properties_requires_url() -> None:
    with pytest.raises(RuntimeError, match="catalog URL"):
        IcebergCatalogConfig().catalog_properties()


def test_catalog_properties_includes_credential_and_warehouse() -> None:
    config = IcebergCatalogConfig(catalog_url="http://c/", credential="id:secret", warehouse="s3://wh")
    props = config.catalog_properties()
    assert props["credential"] == "id:secret"
    assert props["warehouse"] == "s3://wh"


# ── disabled-by-default no-op ─────────────────────────────────────────────────


def test_maybe_register_noop_when_disabled() -> None:
    report, br = _report()
    assert maybe_register_iceberg(report, [br]) is None


def test_register_findings_rejects_disabled_config() -> None:
    report, br = _report()
    with pytest.raises(RuntimeError, match="not configured"):
        register_findings(report, IcebergCatalogConfig(), [br])


# ── deps-absent graceful error ────────────────────────────────────────────────


def test_deps_absent_graceful_error(monkeypatch) -> None:
    def _boom():
        raise RuntimeError("Iceberg catalog export requires pyiceberg. Install with: pip install pyiceberg")

    monkeypatch.setattr(iceberg_catalog, "_require_pyiceberg", _boom)
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="http://c/")
    # catalog built internally -> _require_pyiceberg raises install hint
    with pytest.raises(RuntimeError, match=r"pip install pyiceberg"):
        register_findings(report, config, [br])


# ── round-trip against a fake REST catalog ────────────────────────────────────


def test_round_trip_against_fake_catalog() -> None:
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="http://c/", namespace="lake", table="cves")
    fake = _FakeCatalog()

    result = register_findings(report, config, [br], catalog=fake)

    assert fake.namespaces == [("lake",)]
    assert "lake.cves" in fake.tables
    table = fake.tables["lake.cves"]
    # schema handed to Iceberg must match the shared 28-col Parquet schema
    assert len(table.schema) == 28
    assert table.schema.names[0] == "cve_id"
    assert len(table.appended) == 1
    assert table.appended[0].num_rows == 1
    assert result == {
        "identifier": "lake.cves",
        "rows": 1,
        "snapshot_id": 4242,
        "catalog_url": "http://c/",
    }


def test_round_trip_appends_to_existing_table() -> None:
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="http://c/")
    fake = _FakeCatalog()

    register_findings(report, config, [br], catalog=fake)
    register_findings(report, config, [br], catalog=fake)

    # namespace + table create-if-not-exists are idempotent; two snapshots appended
    table = fake.tables[f"{DEFAULT_NAMESPACE}.{DEFAULT_TABLE}"]
    assert len(table.appended) == 2


def test_maybe_register_uses_env(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_ICEBERG_CATALOG_URL", "http://c/")
    fake = _FakeCatalog()
    monkeypatch.setattr(iceberg_catalog, "_build_catalog", lambda config: fake)

    report, br = _report()
    result = maybe_register_iceberg(report, [br])
    assert result is not None
    assert result["identifier"] == f"{DEFAULT_NAMESPACE}.{DEFAULT_TABLE}"
    assert fake.tables[result["identifier"]].appended[0].num_rows == 1
