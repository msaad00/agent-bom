"""Provenance model + generated control inventory for cloud CSPM benchmarks.

Honesty contract (issue #4120, Foundation):

* Each supported benchmark source is *pinned* — name, version, source URL,
  retrieval date, an optional catalog digest, and a license/access note — in
  :data:`BENCHMARK_PROVENANCE`.
* The control inventory (implemented / automated / manual / unsupported /
  official counts) is *derived* from the code registries plus that provenance,
  never hand-maintained.
* A coverage percentage is published *only* when the authoritative denominator
  and mapping are repository-provenanced and machine-verifiable. CIS Benchmark
  content is license-restricted, so no CIS catalog is vendored here; the
  official denominator stays ``None`` and the percentage is withheld rather than
  fabricated.
* :func:`evaluate_drift` powers a CI gate that fails on catalog, registry,
  duplicate-ID, or classification divergence.

This module is the single source of truth for the registry specs and the
automated/manual classification; :mod:`agent_bom.cloud.benchmark_manifests`
consumes it so the report-exposed manifest and this inventory can never diverge.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

PROVENANCE_SCHEMA_VERSION: Final = 1

# Date the pinned source references below were last verified. Absolute, so the
# provenance record reads the same in any later context.
_RETRIEVED_AT: Final = "2026-07-18"

_CIS_LICENSE_NOTE: Final = (
    "CIS Benchmark content is license-restricted (CIS SecureSuite Member Terms); "
    "referenced by control identifier only — no benchmark text is redistributed in this repository."
)


@dataclass(frozen=True)
class BenchmarkProvenance:
    """A pinned, versioned reference to an authoritative benchmark source.

    ``official_control_count`` and ``source_digest`` are populated only when a
    permissibly-sourced authoritative catalog is checked into the repository
    (``catalog_repository_provenance`` is then ``True``). Until then they stay
    ``None`` and any coverage percentage is withheld.
    """

    provider: str
    benchmark_name: str
    benchmark_version: str
    benchmark_type: str
    source_url: str
    retrieved_at: str
    source_digest: str | None
    license_note: str
    access_mode: str
    catalog_repository_provenance: bool
    official_control_count: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "benchmark_name": self.benchmark_name,
            "benchmark_version": self.benchmark_version,
            "benchmark_type": self.benchmark_type,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "source_digest": self.source_digest,
            "license_note": self.license_note,
            "access_mode": self.access_mode,
            "catalog_repository_provenance": self.catalog_repository_provenance,
            "official_control_count": self.official_control_count,
        }


# ── Registry specs + classification (single source of truth) ────────────────

# provider -> (registry file, registry variable names, human registry label)
REGISTRY_SPECS: Final[dict[str, tuple[str, tuple[str, ...], str]]] = {
    "aws": ("aws_cis_benchmark.py", ("_CHECKS", "_SPECIAL_CHECKS"), "agent_bom.cloud.aws_cis_benchmark:_CHECKS+_SPECIAL_CHECKS"),
    "gcp": ("gcp_cis_benchmark.py", ("all_checks",), "agent_bom.cloud.gcp_cis_benchmark:run_benchmark.all_checks"),
    "azure": ("azure_cis_benchmark.py", ("all_checks",), "agent_bom.cloud.azure_cis_benchmark:run_benchmark.all_checks"),
    "snowflake": ("snowflake_cis_benchmark.py", ("all_checks",), "agent_bom.cloud.snowflake_cis_benchmark:run_benchmark.all_checks"),
    "databricks": ("databricks_security.py", ("_ALL_CHECKS",), "agent_bom.cloud.databricks_security:_ALL_CHECKS"),
}

# Controls implemented as guided/manual verification rather than an automated
# read. Every ID here must exist in the corresponding registry.
MANUAL_CONTROL_IDS: Final[dict[str, tuple[str, ...]]] = {
    "aws": ("1.3",),
    "gcp": ("1.2", "1.3"),
    "azure": (
        "1.3",
        "1.4",
        "1.6",
        "1.8",
        "1.9",
        "1.10",
        "1.11",
        "1.12",
        "1.13",
        "1.14",
        "1.16",
        "1.17",
        "1.18",
        "1.19",
        "1.20",
        "1.21",
        "1.22",
    ),
    "snowflake": (),
    "databricks": (),
}

BENCHMARK_PROVENANCE: Final[dict[str, BenchmarkProvenance]] = {
    "aws": BenchmarkProvenance(
        provider="aws",
        benchmark_name="CIS AWS Foundations",
        benchmark_version="3.0",
        benchmark_type="cis",
        source_url="https://www.cisecurity.org/benchmark/amazon_web_services",
        retrieved_at=_RETRIEVED_AT,
        source_digest=None,
        license_note=_CIS_LICENSE_NOTE,
        access_mode="reference_url_only",
        catalog_repository_provenance=False,
        official_control_count=None,
    ),
    "gcp": BenchmarkProvenance(
        provider="gcp",
        benchmark_name="CIS Google Cloud Platform Foundation",
        benchmark_version="3.0",
        benchmark_type="cis",
        source_url="https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
        retrieved_at=_RETRIEVED_AT,
        source_digest=None,
        license_note=_CIS_LICENSE_NOTE,
        access_mode="reference_url_only",
        catalog_repository_provenance=False,
        official_control_count=None,
    ),
    "azure": BenchmarkProvenance(
        provider="azure",
        benchmark_name="CIS Microsoft Azure Foundations",
        benchmark_version="3.0",
        benchmark_type="cis",
        source_url="https://www.cisecurity.org/benchmark/azure",
        retrieved_at=_RETRIEVED_AT,
        source_digest=None,
        license_note=_CIS_LICENSE_NOTE,
        access_mode="reference_url_only",
        catalog_repository_provenance=False,
        official_control_count=None,
    ),
    "snowflake": BenchmarkProvenance(
        provider="snowflake",
        benchmark_name="CIS Snowflake Foundations",
        benchmark_version="1.0",
        benchmark_type="cis",
        source_url="https://www.cisecurity.org/benchmark/snowflake",
        retrieved_at=_RETRIEVED_AT,
        source_digest=None,
        license_note=_CIS_LICENSE_NOTE,
        access_mode="reference_url_only",
        catalog_repository_provenance=False,
        official_control_count=None,
    ),
    "databricks": BenchmarkProvenance(
        provider="databricks",
        benchmark_name="Databricks Security Best Practices",
        benchmark_version="1.0",
        benchmark_type="vendor_best_practices",
        source_url="https://docs.databricks.com/en/security/index.html",
        retrieved_at=_RETRIEVED_AT,
        source_digest=None,
        license_note=(
            "Databricks security guidance is public vendor documentation; the mapping is first-party and is not a CIS benchmark."
        ),
        access_mode="reference_url_only",
        catalog_repository_provenance=False,
        official_control_count=None,
    ),
}


@dataclass(frozen=True)
class ControlInventory:
    """A generated, machine-verifiable inventory of implemented controls."""

    provider: str
    control_ids: tuple[str, ...]
    automated_control_ids: tuple[str, ...]
    manual_control_ids: tuple[str, ...]
    implemented_control_count: int
    official_control_count: int | None
    unsupported_control_count: int | None
    inventory_digest: str
    provenance: BenchmarkProvenance = field(compare=True)


# ── Inventory generation ────────────────────────────────────────────────────


def _registry_ids(filename: str, *variables: str) -> tuple[str, ...]:
    """Read the explicit check-function registries into stable control IDs."""
    tree = ast.parse((Path(__file__).with_name(filename)).read_text())
    ids: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value: ast.expr = node.value
        elif isinstance(node, ast.AnnAssign):
            if node.value is None:
                continue
            targets = [node.target]
            value = node.value
        else:
            continue
        if not any(isinstance(item, ast.Name) and item.id in variables for item in targets):
            continue
        if not isinstance(value, (ast.List, ast.Tuple)):
            continue
        is_all_checks = any(isinstance(target, ast.Name) and target.id == "all_checks" for target in targets)
        for item in value.elts:
            if isinstance(item, ast.Tuple) and is_all_checks:
                check_id = item.elts[0]
                if isinstance(check_id, ast.Constant) and isinstance(check_id.value, str):
                    ids.append(check_id.value)
                continue
            fn = item.elts[1] if isinstance(item, ast.Tuple) else item
            if isinstance(fn, ast.Name) and fn.id.startswith("_check_"):
                ids.append(fn.id.removeprefix("_check_").replace("_", "."))
    return tuple(ids)


def _digest(provider: str, control_ids: tuple[str, ...], manual_ids: tuple[str, ...]) -> str:
    payload = json.dumps(
        {"provider": provider, "control_ids": sorted(control_ids), "manual_control_ids": sorted(manual_ids)},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def build_control_inventory(provider: str) -> ControlInventory:
    """Derive the control inventory for ``provider`` from its code registry."""
    filename, variables, _label = REGISTRY_SPECS[provider]
    control_ids = _registry_ids(filename, *variables)
    manual_ids = MANUAL_CONTROL_IDS[provider]
    automated = tuple(sorted(set(control_ids) - set(manual_ids)))
    prov = BENCHMARK_PROVENANCE[provider]
    official = prov.official_control_count if prov.catalog_repository_provenance else None
    unsupported = official - len(control_ids) if official is not None else None
    return ControlInventory(
        provider=provider,
        control_ids=tuple(control_ids),
        automated_control_ids=automated,
        manual_control_ids=tuple(sorted(manual_ids)),
        implemented_control_count=len(control_ids),
        official_control_count=official,
        unsupported_control_count=unsupported,
        inventory_digest=_digest(provider, control_ids, manual_ids),
        provenance=prov,
    )


def coverage_percentage(inventory: ControlInventory) -> float | None:
    """Return a coverage % only when the denominator is machine-verifiable.

    A percentage requires a repository-provenanced authoritative catalog with a
    positive official control count. Otherwise it is withheld (``None``).
    """
    prov = inventory.provenance
    if not prov.catalog_repository_provenance:
        return None
    if not prov.official_control_count:
        return None
    return round(100.0 * inventory.implemented_control_count / prov.official_control_count, 1)


# ── Committed inventory artifact + drift gate ───────────────────────────────

INVENTORY_PATH: Final = Path(__file__).with_name("benchmark_inventory.json")


def _inventory_record(provider: str) -> dict[str, Any]:
    inv = build_control_inventory(provider)
    return {
        "control_ids": list(inv.control_ids),
        "automated_control_ids": list(inv.automated_control_ids),
        "manual_control_ids": list(inv.manual_control_ids),
        "implemented_control_count": inv.implemented_control_count,
        "official_control_count": inv.official_control_count,
        "unsupported_control_count": inv.unsupported_control_count,
        "coverage_percentage": coverage_percentage(inv),
        "inventory_digest": inv.inventory_digest,
        "provenance": inv.provenance.to_dict(),
    }


def build_drift_records() -> dict[str, dict[str, Any]]:
    """Live inventory records derived from the current code registries."""
    return {provider: _inventory_record(provider) for provider in REGISTRY_SPECS}


def render_committed_inventory() -> str:
    """Deterministic JSON serialization of the generated control inventory."""
    document = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "generated_from": "code registries (agent_bom.cloud.benchmark_provenance.build_drift_records)",
        "providers": build_drift_records(),
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def load_committed_inventory() -> dict[str, dict[str, Any]]:
    """Return the committed per-provider inventory records."""
    document = json.loads(INVENTORY_PATH.read_text())
    providers: dict[str, dict[str, Any]] = document["providers"]
    return providers


def evaluate_drift(committed: dict[str, dict[str, Any]], live: dict[str, dict[str, Any]]) -> list[str]:
    """Return a list of drift problems; empty means catalog + registries agree.

    Fails on: provider-set change, duplicate control IDs, registry count/digest
    divergence, automated/manual classification divergence, and any coverage
    percentage or official denominator published without repository provenance.
    """
    problems: list[str] = []
    committed_document = committed.get("providers", committed) if "providers" in committed else committed

    missing = set(committed_document) - set(live)
    extra = set(live) - set(committed_document)
    if missing:
        problems.append(f"provider set divergence — committed providers missing from registries: {sorted(missing)}")
    if extra:
        problems.append(f"provider set divergence — registries have providers absent from committed catalog: {sorted(extra)}")

    for provider in sorted(set(committed_document) & set(live)):
        expected = committed_document[provider]
        current = live[provider]
        control_ids = list(current["control_ids"])
        automated = list(current["automated_control_ids"])
        manual = list(current["manual_control_ids"])
        prov = current.get("provenance", {})

        if len(control_ids) != len(set(control_ids)):
            dupes = sorted({cid for cid in control_ids if control_ids.count(cid) > 1})
            problems.append(f"{provider}: duplicate control id(s) in registry: {dupes}")

        if current["implemented_control_count"] != len(control_ids):
            problems.append(
                f"{provider}: registry count divergence — implemented_control_count "
                f"{current['implemented_control_count']} != {len(control_ids)} control ids"
            )

        if not set(manual) <= set(control_ids):
            orphan = sorted(set(manual) - set(control_ids))
            problems.append(f"{provider}: classification divergence — manual id(s) absent from registry: {orphan}")
        if set(automated) & set(manual):
            problems.append(f"{provider}: classification divergence — control(s) both automated and manual")
        if set(automated) | set(manual) != set(control_ids):
            problems.append(f"{provider}: classification divergence — automated∪manual does not equal the registry")

        if sorted(control_ids) != sorted(expected["control_ids"]):
            problems.append(f"{provider}: registry/catalog divergence — control id set changed; regenerate benchmark_inventory.json")

        if sorted(automated) != sorted(expected["automated_control_ids"]) or sorted(manual) != sorted(expected["manual_control_ids"]):
            problems.append(f"{provider}: classification divergence — automated/manual split changed; regenerate benchmark_inventory.json")

        # The committed record must be internally consistent (its digest matches
        # its own control set) so a hand-edit of the JSON cannot slip through.
        committed_digest = _digest(provider, tuple(expected["control_ids"]), tuple(expected["manual_control_ids"]))
        if expected["inventory_digest"] != committed_digest:
            problems.append(
                f"{provider}: committed inventory digest inconsistent with its control set; regenerate benchmark_inventory.json"
            )

        if current["inventory_digest"] != expected["inventory_digest"]:
            problems.append(f"{provider}: registry/catalog divergence — inventory digest changed; regenerate benchmark_inventory.json")

        expected_prov = expected.get("provenance", {})
        for pinned in ("source_url", "benchmark_version", "benchmark_type"):
            if prov.get(pinned) != expected_prov.get(pinned):
                problems.append(
                    f"{provider}: provenance divergence — {pinned} changed "
                    f"({expected_prov.get(pinned)!r} -> {prov.get(pinned)!r}); regenerate benchmark_inventory.json"
                )

        provenanced = bool(prov.get("catalog_repository_provenance")) and prov.get("official_control_count")
        if current.get("coverage_percentage") is not None and not provenanced:
            problems.append(f"{provider}: unverifiable coverage percentage published without a repository-provenanced denominator")
        if current.get("official_control_count") is not None and not prov.get("catalog_repository_provenance"):
            problems.append(f"{provider}: official denominator set without repository catalog provenance")

    return problems
