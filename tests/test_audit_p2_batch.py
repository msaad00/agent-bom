"""P2 audit-polish batch: extra=forbid on inline route models + framework-scoped narrative."""

import pytest
from pydantic import ValidationError


@pytest.mark.parametrize(
    "module, cls_name, valid",
    [
        ("agent_bom.api.routes.graph", "GraphQueryRequest", {"roots": ["n1"]}),
        ("agent_bom.api.routes.graph", "PresetCreate", {"name": "p", "filters": {}}),
        ("agent_bom.api.routes.enterprise", "BrowserSessionRequest", {"api_key": "k"}),
        ("agent_bom.api.routes.enterprise", "AuditExportVerifyRequest", {"payload": {}, "signature": "x" * 64}),
    ],
)
def test_inline_route_models_reject_unknown_fields(module, cls_name, valid):
    import importlib

    cls = getattr(importlib.import_module(module), cls_name)
    cls(**valid)  # legit body still works
    with pytest.raises(ValidationError):
        cls(**{**valid, "definitely_unknown_field": 1})


def test_compliance_narrative_remediation_scoped_to_requested_framework():
    from agent_bom.output.compliance_narrative import _build_remediation_impact

    br = [
        {
            "package": "flask@0.12",
            "fixed_version": "2.3.2",
            "soc2_tags": ["CC6.1"],
            "iso_27001_tags": ["A.5.19"],
            "nist_csf_tags": ["ID.RA-01"],
        }
    ]
    all_fw = {f for i in _build_remediation_impact(br) for f in i.frameworks_impacted}
    soc2 = {f for i in _build_remediation_impact(br, "soc2") for f in i.frameworks_impacted}
    assert len(all_fw) >= 3  # unscoped lists every framework
    assert soc2 and all("SOC" in f for f in soc2)  # scoped: only SOC 2
