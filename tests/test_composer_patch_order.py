"""Composer patch aliases must not be mistaken for pre-release versions."""

import pytest

from agent_bom.version_utils import compare_version_order, version_in_range


@pytest.mark.parametrize("ecosystem", ["composer", "packagist"])
@pytest.mark.parametrize("suffix", ["patch1", "patch.1", "PATCH1"])
def test_composer_patch_alias_matches_patchlevel(ecosystem, suffix):
    version = f"1.0.0-{suffix}"
    assert compare_version_order(version, "1.0.0", ecosystem) == 1
    assert compare_version_order(version, "1.0.0-pl1", ecosystem) == 0
    assert compare_version_order("1.0.0-pl2", version, ecosystem) == 1
    assert version_in_range(version, "1.0.0", "1.0.0-p2", None, ecosystem)
    assert not version_in_range(version, "0", "1.0.0", None, ecosystem)


def test_native_php_keeps_its_unrecognized_qualifier_order():
    assert compare_version_order("1.0.0-patch1", "1.0.0", "php") == -1
