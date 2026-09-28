"""Cross-surface parity before consolidating duplicated pure judgments."""

from datetime import timezone

import pytest

from agent_bom import transitive, version_utils
from agent_bom.compliance_nist_catalog import evaluated_control_status
from agent_bom.core import credential_policy
from agent_bom.graph import nhi_governance
from agent_bom.output.compliance_narrative import _control_status


@pytest.mark.parametrize(
    "module,expected",
    [
        ("", ""),
        ("github.com/user/repo", "github.com/user/repo"),
        ("GitHub.com/Azure/RepoV2", "!git!hub.com/!azure/!repo!v2"),
        ("A/B!C", "!a/!b!!c"),
        ("École/Σ", "!école/!σ"),
    ],
)
def test_go_proxy_encoding_parity(module, expected):
    assert version_utils._go_encode_module(module) == expected
    assert transitive._go_encode_module(module) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        (False, None),
        (123, None),
        ({}, None),
        ("", None),
        ("  ", None),
        ("not-a-time", None),
        ("2026-09-27", "2026-09-27T00:00:00+00:00"),
        (" 2026-09-27T12:34:56Z ", "2026-09-27T12:34:56+00:00"),
        ("2026-09-27T12:34:56.123", "2026-09-27T12:34:56.123000+00:00"),
        ("2026-09-27T12:34:56+05:30", "2026-09-27T12:34:56+05:30"),
    ],
)
def test_credential_and_governance_timestamp_parity(raw, expected):
    for parser in (credential_policy._parse_timestamp, nhi_governance._parse_timestamp):
        result = parser(raw)
        assert (result.isoformat() if result else None) == expected
        if result and result.utcoffset().total_seconds() == 0:
            assert result.tzinfo == timezone.utc


@pytest.mark.parametrize(
    "counts,expected",
    [
        ({}, "not_evaluated"),
        ({"unrated": 5}, "not_evaluated"),
        ({"critical": 1, "unrated": 5}, "fail"),
        ({"high": 1, "medium": 4}, "fail"),
        ({"medium": 2, "low": 1}, "warning"),
        ({"low": 1}, "warning"),
        ({"critical": 0, "high": 0, "medium": 0, "low": 0}, "not_evaluated"),
    ],
)
def test_catalog_and_narrative_control_status_parity(counts, expected):
    original = dict(counts)
    assert evaluated_control_status(counts) == expected
    assert _control_status(counts) == expected
    assert counts == original
