"""Optional Gremlin response normalization preserves adapter behavior."""

from unittest.mock import Mock

import pytest


@pytest.mark.parametrize("value, expected", [(None, []), ([1, 2], [1, 2]), (1, [1])])
def test_neptune_result_adapter_preserves_plain_values(value, expected):
    from agent_bom.api.storage.neptune_results import normalize_neptune_result

    assert normalize_neptune_result(value) == expected


def test_neptune_result_adapter_unwraps_driver_future():
    from agent_bom.api.storage.neptune_results import normalize_neptune_result

    result = Mock()
    result.all.return_value.result.return_value = ["node"]
    assert normalize_neptune_result(result) == ["node"]
