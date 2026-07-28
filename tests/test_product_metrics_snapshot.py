"""Contract tests for the generated product-metrics snapshot."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import cast

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "product_metrics_snapshot.py"
METRICS_JSON = ROOT / "docs" / "PRODUCT_METRICS.json"
METRICS_MARKDOWN = ROOT / "docs" / "PRODUCT_METRICS.md"


def _load_metrics_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("product_metrics_snapshot", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_compliance_metric_uses_the_canonical_framework_count() -> None:
    module = _load_metrics_script()
    snapshot = module.build_snapshot()
    metrics = cast(list[dict[str, object]], snapshot["metrics"])
    compliance = next(metric for metric in metrics if metric["name"] == "Compliance surfaces")
    tag_mapped_count = len(TAG_MAPPED_FRAMEWORKS)

    assert tag_mapped_count == 15
    assert compliance["value"] == tag_mapped_count + 1 == 16
    assert compliance["notes"] == f"{tag_mapped_count} tag-mapped frameworks plus the OWASP AISVS benchmark surface."

    checked_in = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    assert checked_in["version"] == snapshot["version"]
    assert checked_in["metrics"] == snapshot["metrics"]
    checked_in_compliance = next(metric for metric in checked_in["metrics"] if metric["name"] == "Compliance surfaces")
    assert checked_in_compliance == compliance
    assert (
        f"| Compliance surfaces | {compliance['value']} | `src/agent_bom/compliance_coverage.py` | {compliance['notes']} |"
        in METRICS_MARKDOWN.read_text(encoding="utf-8")
    )
