import pytest

from agent_bom.parsers.file_limits import ManifestTooLargeError, read_json_limited, read_text_limited


def test_read_text_limited_rejects_oversized_manifest(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text("x" * 11)

    with pytest.raises(ManifestTooLargeError):
        read_text_limited(path, max_bytes=10)


def test_read_json_limited_parses_within_limit(tmp_path):
    path = tmp_path / "composer.lock"
    path.write_text('{"packages": []}')

    assert read_json_limited(path, max_bytes=100) == {"packages": []}
