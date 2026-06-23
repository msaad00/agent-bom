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
    "cosmosdb": "azure-mgmt-cosmosdb",
    "keyvault": "azure-mgmt-keyvault",
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
