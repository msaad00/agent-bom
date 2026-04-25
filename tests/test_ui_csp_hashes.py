from __future__ import annotations

import base64
import hashlib

from scripts.generate_ui_csp_hashes import generate_hash_manifest


def _sha256_source(value: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")


def test_generate_ui_csp_hashes_extracts_inline_scripts_and_styles(tmp_path):
    ui_dist = tmp_path / "ui_dist"
    ui_dist.mkdir()
    (ui_dist / "index.html").write_text(
        "<html><head><style>.x{color:red}</style></head>"
        "<body><script>window.__next_f=[]</script><script src='/app.js'></script></body></html>",
        encoding="utf-8",
    )

    manifest = generate_hash_manifest(ui_dist)

    assert manifest["html_file_count"] == 1
    assert manifest["script_hashes"] == [_sha256_source("window.__next_f=[]")]
    assert manifest["style_hashes"] == [_sha256_source(".x{color:red}")]
