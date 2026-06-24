"""Guards for Azure cloud-scan coverage and honest CIS reporting.

Both regressions were caught by a live read-only scan: the published
``agent-bom[azure]`` extra shipped only a subset of the ``azure.mgmt`` SDKs the
code imports (so most inventory + CIS checks errored out), and the CIS summary
reported a ``pass_rate`` with no visibility into how many checks could not be
evaluated.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.azure_cis_benchmark import AzureCISReport

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src" / "agent_bom"

# azure.mgmt module -> pip distribution (dots become hyphens)
_MODULE_TO_DIST = {
    "appcontainers": "azure-mgmt-appcontainers",
    "authorization": "azure-mgmt-authorization",
    "cognitiveservices": "azure-mgmt-cognitiveservices",
    "compute": "azure-mgmt-compute",
    "containerinstance": "azure-mgmt-containerinstance",
    "containerregistry": "azure-mgmt-containerregistry",
    "containerservice": "azure-mgmt-containerservice",
    "cosmosdb": "azure-mgmt-cosmosdb",
    "apimanagement": "azure-mgmt-apimanagement",
    "eventhub": "azure-mgmt-eventhub",
    "frontdoor": "azure-mgmt-frontdoor",
    "keyvault": "azure-mgmt-keyvault",
    "redis": "azure-mgmt-redis",
    "servicebus": "azure-mgmt-servicebus",
    "managementgroups": "azure-mgmt-managementgroups",
    "machinelearningservices": "azure-mgmt-machinelearningservices",
    "monitor": "azure-mgmt-monitor",
    "msi": "azure-mgmt-msi",
    "network": "azure-mgmt-network",
    "rdbms": "azure-mgmt-rdbms",
    "resource": "azure-mgmt-resource",
    "security": "azure-mgmt-security",
    "sql": "azure-mgmt-sql",
    "storage": "azure-mgmt-storage",
    "web": "azure-mgmt-web",
}


def _imported_mgmt_modules() -> set[str]:
    mods: set[str] = set()
    for py in _SRC.rglob("*.py"):
        for m in re.findall(r"azure\.mgmt\.([a-z_]+)", py.read_text()):
            mods.add(m)
    return mods


def _declared_azure_dists() -> set[str]:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text())
    deps = data["project"]["optional-dependencies"]["azure"]
    return {re.split(r"[><=!~ ]", d, maxsplit=1)[0].strip() for d in deps}


def test_azure_extra_declares_every_imported_mgmt_sdk() -> None:
    """Every ``azure.mgmt.*`` the code imports must be in the ``azure`` extra."""
    declared = _declared_azure_dists()
    missing = []
    for module in _imported_mgmt_modules():
        dist = _MODULE_TO_DIST.get(module)
        assert dist is not None, f"unmapped azure.mgmt.{module} — add to _MODULE_TO_DIST"
        if dist not in declared:
            missing.append(dist)
    assert not missing, f"azure extra missing imported SDKs: {sorted(missing)}"


# Non-mgmt azure namespaces are transitive (pulled in by core) or genuinely
# optional — only those mapped here are required in the extra. azure.core /
# azure.common ship transitively with any azure SDK, so they are not required.
_TRANSITIVE_AZURE = {"core", "common"}


def _azure_dist_for(module: str) -> str | None:
    """Map a top-level azure import path to its required PyPI distribution.

    Returns None for transitively-provided namespaces (azure.core/common) that
    need not be declared explicitly.
    """
    parts = module.split(".")
    if len(parts) < 2 or parts[1] in _TRANSITIVE_AZURE:
        return None
    if parts[1] == "mgmt":
        return f"azure-mgmt-{parts[2].replace('_', '')}"
    if parts[1] == "ai":
        return f"azure-ai-{parts[2].replace('_', '')}"
    if parts[1] == "keyvault":
        return f"azure-keyvault-{parts[2].replace('_', '')}"
    if parts[1] == "identity":
        return "azure-identity"
    if parts[1] == "storage":
        return f"azure-storage-{parts[2].replace('_', '')}" if len(parts) > 2 else "azure-storage"
    return f"azure-{parts[1].replace('_', '')}"


def test_azure_extra_declares_every_imported_azure_sdk() -> None:
    """Every azure SDK the cloud code imports — mgmt AND data-plane (azure.ai,
    azure.keyvault, …) — must be in the ``azure`` extra, or it is dead-on-arrival
    for installed users. Caught live: azure-ai-projects (AI Foundry) and
    azure-keyvault-keys/secrets (CIS key/secret expiry) were missing → those
    features silently skipped.
    """
    declared = _declared_azure_dists()
    imports: set[str] = set()
    for py in _SRC.rglob("*.py"):
        for m in re.findall(r"(?:from|import)\s+(azure(?:\.[a-z_]+)+)", py.read_text()):
            imports.add(m)
    missing = []
    for module in sorted(imports):
        dist = _azure_dist_for(module)
        if dist and dist not in declared:
            missing.append((module, dist))
    assert not missing, f"azure extra missing imported SDKs (dead-on-arrival): {missing}"


def _result_with(statuses: list[CheckStatus]) -> AzureCISReport:
    checks = [CISCheckResult(check_id=f"c{i}", title=f"check {i}", status=s, severity="medium") for i, s in enumerate(statuses)]
    return AzureCISReport(checks=checks, subscription_id="sub")


def test_cis_summary_surfaces_uneval_checks() -> None:
    """A run where almost everything errored must not look like a clean pass."""
    # 6 pass, 0 fail, 72 errored, 17 n/a — the live shape before the SDK fix.
    res = _result_with([CheckStatus.PASS] * 6 + [CheckStatus.ERROR] * 72 + [CheckStatus.NOT_APPLICABLE] * 17)
    d = res.to_dict()
    assert d["pass_rate"] == 100.0  # pass_rate is over evaluated checks only...
    # ...so the coverage fields are what stop it from being read as "95/95 clean".
    assert d["errored"] == 72
    assert d["not_applicable"] == 17
    assert d["evaluated"] == 6
    assert d["total"] == 95


def test_cis_pass_rate_is_over_evaluated_not_total() -> None:
    res = _result_with([CheckStatus.PASS] * 3 + [CheckStatus.FAIL] * 1 + [CheckStatus.ERROR] * 6)
    d = res.to_dict()
    assert d["evaluated"] == 4
    assert d["pass_rate"] == 75.0
    assert d["errored"] == 6
