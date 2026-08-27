"""Iceberg REST-catalog registration contract for data-lake interop (#3499)."""

from __future__ import annotations

import tomllib
from pathlib import Path

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
        self._schema = schema
        self.appended = []

    def schema(self):
        return self._schema

    def append(self, arrow_table):
        self.appended.append(arrow_table)

    def current_snapshot(self):
        return _FakeSnapshot()


class _FakeSchemaUpdate:
    def __init__(self, table: "_FakeLegacyTable") -> None:
        self._table = table
        self._target = None

    def union_by_name(self, schema):
        self._target = schema
        return self

    def commit(self) -> None:
        self._table._schema = self._target
        self._table.schema_commits += 1


class _FakeLegacyTable(_FakeTable):
    def __init__(self, identifier, schema):
        super().__init__(identifier, schema)
        self.schema_commits = 0

    def update_schema(self):
        return _FakeSchemaUpdate(self)


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


def test_lake_extra_installs_the_documented_iceberg_runtime() -> None:
    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())
    lake = pyproject["project"]["optional-dependencies"]["lake"]
    assert any(dep.startswith("pyiceberg") for dep in lake)


def test_lake_extra_is_covered_by_the_extras_dependency_audit() -> None:
    workflow = (Path(__file__).parents[1] / ".github/workflows/extras-audit.yml").read_text()
    assert 'extras: "postgres dashboard lake"' in workflow


# ── round-trip against a fake REST catalog ────────────────────────────────────


def test_round_trip_against_fake_catalog() -> None:
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="http://c/", namespace="lake", table="cves")
    fake = _FakeCatalog()

    result = register_findings(report, config, [br], catalog=fake)

    assert fake.namespaces == [("lake",)]
    assert "lake.cves" in fake.tables
    table = fake.tables["lake.cves"]
    # Schema handed to Iceberg is the same additively versioned schema emitted
    # by the flat Parquet artifact.
    assert len(table.schema()) == 40
    assert table.schema().names[0] == "cve_id"
    assert table.schema().names[-3:] == ["lifecycle_status", "symbol_reachability_reason", "runtime_dependency_chain"]
    assert len(table.appended) == 1
    assert table.appended[0].num_rows == 1
    assert result == {
        "identifier": "lake.cves",
        "rows": 1,
        "snapshot_id": 4242,
        "catalog_url": "http://c",
    }


def test_result_never_echoes_catalog_url_credentials_or_query_tokens() -> None:
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="https://client:secret@catalog.example/v1?token=hidden")

    result = register_findings(report, config, [br], catalog=_FakeCatalog())

    assert result["catalog_url"] == "https://catalog.example"
    assert "secret" not in str(result)
    assert "hidden" not in str(result)


def test_round_trip_appends_to_existing_table() -> None:
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="http://c/")
    fake = _FakeCatalog()

    register_findings(report, config, [br], catalog=fake)
    register_findings(report, config, [br], catalog=fake)

    # namespace + table create-if-not-exists are idempotent; two snapshots appended
    table = fake.tables[f"{DEFAULT_NAMESPACE}.{DEFAULT_TABLE}"]
    assert len(table.appended) == 2


def test_existing_additive_table_schema_is_evolved_before_append() -> None:
    report, br = _report()
    config = IcebergCatalogConfig(catalog_url="http://c/")
    fake = _FakeCatalog()
    current = iceberg_catalog.to_arrow_table(report, [br])
    legacy = _FakeLegacyTable(config.identifier, current.select(current.schema.names[:31]).schema)
    fake.tables[config.identifier] = legacy

    register_findings(report, config, [br], catalog=fake)

    assert legacy.schema_commits == 1
    assert legacy.schema().names == current.schema.names
    assert len(legacy.appended) == 1


def test_real_pyiceberg_catalog_evolves_v2_and_commits_v4_snapshot(tmp_path) -> None:
    pytest.importorskip("pyiceberg")
    from pyiceberg.catalog.memory import InMemoryCatalog

    report, br = _report()
    current = iceberg_catalog.to_arrow_table(report, [br])
    catalog = InMemoryCatalog("test", warehouse=f"file://{tmp_path.resolve()}")
    catalog.create_namespace((DEFAULT_NAMESPACE,))
    catalog.create_table(
        f"{DEFAULT_NAMESPACE}.{DEFAULT_TABLE}",
        schema=current.select(current.schema.names[:31]).schema,
    )

    result = register_findings(
        report,
        IcebergCatalogConfig(catalog_url="memory://"),
        [br],
        catalog=catalog,
    )

    table = catalog.load_table(f"{DEFAULT_NAMESPACE}.{DEFAULT_TABLE}")
    assert len(table.schema().fields) == 40
    assert table.scan().to_arrow().num_rows == 1
    assert result["rows"] == 1
    assert result["snapshot_id"] is not None


def test_maybe_register_uses_env(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_ICEBERG_CATALOG_URL", "http://c/")
    fake = _FakeCatalog()
    monkeypatch.setattr(iceberg_catalog, "_build_catalog", lambda config: fake)

    report, br = _report()
    result = maybe_register_iceberg(report, [br])
    assert result is not None
    assert result["identifier"] == f"{DEFAULT_NAMESPACE}.{DEFAULT_TABLE}"
    assert fake.tables[result["identifier"]].appended[0].num_rows == 1
