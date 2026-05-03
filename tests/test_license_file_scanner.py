"""Tests for agent_bom.license_file_scanner (#872)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.license_file_scanner import (
    detect_spdx_from_license_text,
    detect_spdx_from_text,
    is_license_filename,
    scan_directory,
    scan_license_file,
    scan_source_header,
)

# ─── SPDX tag extraction ──────────────────────────────────────────────────────


def test_detect_spdx_from_text_simple():
    assert detect_spdx_from_text("# SPDX-License-Identifier: MIT") == "MIT"


def test_detect_spdx_from_text_expression():
    result = detect_spdx_from_text("// SPDX-License-Identifier: Apache-2.0 OR MIT")
    assert result == "Apache-2.0 OR MIT"


def test_detect_spdx_from_text_missing():
    assert detect_spdx_from_text("No license info here.") is None


def test_detect_spdx_from_text_case_insensitive():
    assert detect_spdx_from_text("# spdx-license-identifier: GPL-3.0-only") == "GPL-3.0-only"


# ─── License text pattern matching ───────────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        ("MIT License\nPermission is hereby granted, free of charge", "MIT"),
        ("Apache License\nVersion 2.0", "Apache-2.0"),
        ("GNU GENERAL PUBLIC LICENSE\nVersion 3", "GPL-3.0-only"),
        ("GNU GENERAL PUBLIC LICENSE\nVersion 2", "GPL-2.0-only"),
        ("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3", "AGPL-3.0-only"),
        ("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3", "LGPL-3.0-only"),
        ("Mozilla Public License, Version 2.0", "MPL-2.0"),
        ("BSD 2-Clause", "BSD-2-Clause"),
        ("BSD 3-Clause", "BSD-3-Clause"),
        ("ISC License", "ISC"),
        ("The Unlicense", "Unlicense"),
        ("Server Side Public License", "SSPL-1.0"),
        ("Business Source License", "BUSL-1.1"),
        ("Elastic License 2.0", "Elastic-2.0"),
        ("Creative Commons Zero 1.0", "CC0-1.0"),
    ],
)
def test_detect_spdx_from_license_text(text, expected):
    assert detect_spdx_from_license_text(text) == expected


def test_detect_spdx_from_license_text_unknown():
    assert detect_spdx_from_license_text("Some proprietary license text") is None


# ─── License filename detection ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename",
    ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.LESSER", "NOTICE", "UNLICENSE"],
)
def test_is_license_filename_positive(tmp_path, filename):
    p = tmp_path / filename
    p.touch()
    assert is_license_filename(p)


def test_is_license_filename_negative(tmp_path):
    p = tmp_path / "main.py"
    p.touch()
    assert not is_license_filename(p)


# ─── scan_license_file ────────────────────────────────────────────────────────


def test_scan_license_file_spdx_tag(tmp_path):
    f = tmp_path / "LICENSE"
    f.write_text("SPDX-License-Identifier: MIT\nMIT License text...", encoding="utf-8")
    result = scan_license_file(f)
    assert result is not None
    assert result.spdx_id == "MIT"
    assert result.detection_method == "spdx_identifier"
    assert result.confidence == "high"


def test_scan_license_file_text_pattern(tmp_path):
    f = tmp_path / "LICENSE"
    f.write_text("Apache License\nVersion 2.0", encoding="utf-8")
    result = scan_license_file(f)
    assert result is not None
    assert result.spdx_id == "Apache-2.0"
    assert result.detection_method == "text_pattern"
    assert result.confidence == "medium"


def test_scan_license_file_unrecognised(tmp_path):
    f = tmp_path / "LICENSE"
    f.write_text("Proprietary — all rights reserved.", encoding="utf-8")
    assert scan_license_file(f) is None


def test_scan_license_file_missing():
    assert scan_license_file(Path("/nonexistent/LICENSE")) is None


# ─── scan_source_header ───────────────────────────────────────────────────────


def test_scan_source_header_found(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("# SPDX-License-Identifier: Apache-2.0\n\ndef main(): pass\n", encoding="utf-8")
    result = scan_source_header(f)
    assert result is not None
    assert result.spdx_id == "Apache-2.0"
    assert result.detection_method == "source_header"


def test_scan_source_header_not_in_header(tmp_path):
    f = tmp_path / "main.py"
    content = "\n" * 25 + "# SPDX-License-Identifier: MIT\n"
    f.write_text(content, encoding="utf-8")
    assert scan_source_header(f) is None


def test_scan_source_header_missing():
    assert scan_source_header(Path("/nonexistent/file.py")) is None


# ─── scan_directory ───────────────────────────────────────────────────────────


def test_scan_directory_mit_license(tmp_path):
    (tmp_path / "LICENSE").write_text("SPDX-License-Identifier: MIT\nMIT License", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert "MIT" in result.unique_spdx_ids
    assert len(result.license_files) == 1


def test_scan_directory_source_headers(tmp_path):
    (tmp_path / "app.py").write_text("# SPDX-License-Identifier: Apache-2.0\nprint('hi')\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert "Apache-2.0" in result.unique_spdx_ids
    assert len(result.source_headers) == 1


def test_scan_directory_skips_hidden(tmp_path):
    hidden = tmp_path / ".git"
    hidden.mkdir()
    (hidden / "LICENSE").write_text("MIT License\nPermission is hereby granted", encoding="utf-8")
    result = scan_directory(tmp_path)
    # .git is hidden — should be skipped
    assert len(result.license_files) == 0


def test_scan_directory_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "LICENSE").write_text("MIT License\nPermission is hereby granted", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert len(result.license_files) == 0


def test_scan_directory_multiple_licenses(tmp_path):
    (tmp_path / "LICENSE").write_text("SPDX-License-Identifier: MIT\n", encoding="utf-8")
    sub = tmp_path / "vendor"
    sub.mkdir()
    (sub / "LICENSE").write_text("Apache License\nVersion 2.0", encoding="utf-8")
    result = scan_directory(tmp_path)
    assert "MIT" in result.unique_spdx_ids
    assert "Apache-2.0" in result.unique_spdx_ids


def test_scan_directory_empty(tmp_path):
    result = scan_directory(tmp_path)
    assert result.unique_spdx_ids == []
    assert result.all_results == []


def test_scan_directory_not_a_dir(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hello")
    result = scan_directory(f)
    assert result.all_results == []


def test_scan_directory_to_dict(tmp_path):
    (tmp_path / "LICENSE").write_text("SPDX-License-Identifier: MIT\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    d = result.to_dict()
    assert d["unique_spdx_ids"] == ["MIT"]
    assert "license_files" in d
    assert "source_header_count" in d


def test_scan_directory_disable_source_headers(tmp_path):
    (tmp_path / "main.py").write_text("# SPDX-License-Identifier: MIT\nprint('hi')\n", encoding="utf-8")
    result = scan_directory(tmp_path, scan_source_headers=False)
    assert len(result.source_headers) == 0
