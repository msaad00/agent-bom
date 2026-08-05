from __future__ import annotations

import base64
import hashlib
import json

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


def test_generate_ui_csp_hashes_covers_beforeinteractive_bootstrap_scripts(tmp_path):
    """`next/script` beforeInteractive bodies must be hashed, not just <script> tags.

    Next does not emit these as inline tags. It serializes the body into
    ``self.__next_s`` and its ``appBootstrap`` runtime builds a script element
    whose text is exactly the ``children`` string, then appends it -- so the
    browser evaluates that text and checks it against ``script-src-elem``.

    Hashing only the tags found in the HTML therefore covered the *wrapper*
    push and never the payload that actually runs, and the shipped CSP blocked
    every beforeInteractive script. The theme bootstrap was one of them: blocked
    on every page load in production, which is a flash of the wrong theme for
    anyone whose stored preference is not the default.
    """
    theme_body = '\n(function(){document.documentElement.dataset.theme="dark";})();\n'
    ui_dist = tmp_path / "ui_dist"
    ui_dist.mkdir()
    (ui_dist / "index.html").write_text(
        "<html><body>"
        '<script>(self.__next_s=self.__next_s||[]).push(["/runtime-config.js",{}])</script>'
        f"<script>(self.__next_s=self.__next_s||[]).push([0,{json.dumps({'children': theme_body})}])</script>"
        "</body></html>",
        encoding="utf-8",
    )

    manifest = generate_hash_manifest(ui_dist)

    assert _sha256_source(theme_body) in manifest["script_hashes"], (
        "the beforeInteractive body the browser executes is missing from the CSP allowlist"
    )


def test_external_bootstrap_entries_contribute_no_inline_hash(tmp_path):
    """An entry with a `src` loads externally -- there is no inline body to hash."""
    ui_dist = tmp_path / "ui_dist"
    ui_dist.mkdir()
    (ui_dist / "index.html").write_text(
        '<html><body><script src="/x.js"></script><script src="/y.js"></script></body></html>',
        encoding="utf-8",
    )
    assert generate_hash_manifest(ui_dist)["script_hashes"] == []
