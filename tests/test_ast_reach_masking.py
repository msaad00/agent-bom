"""Compiled-language reachability must mask comments + string literals (bug-fix).

The Rust/Java/Ruby/C# call-site extractors ran ``finditer`` over RAW source, so a
dependency symbol mentioned only inside a ``//``/``#`` comment or a string
literal was emitted as a real call site — a reachability over-claim that flips a
non-reachable CVE to ``function_reachable``. Each extractor must mask comments +
strings first, exactly like the PHP/Swift analyzers. A real call must still be
captured.
"""

from __future__ import annotations

from agent_bom.ast_csharp import _csharp_call_sites
from agent_bom.ast_java import _java_call_sites
from agent_bom.ast_ruby import _ruby_call_sites
from agent_bom.ast_rust import _rust_call_sites


def _names(fn, body: str) -> set[str]:
    return {site.name for site in fn(body, line_offset=0)}


# --------------------------------------------------------------------------- #
# Rust                                                                        #
# --------------------------------------------------------------------------- #
def test_rust_real_call_captured() -> None:
    assert "client.request" in _names(_rust_call_sites, "client.request(url);")


def test_rust_comment_and_string_mentions_masked() -> None:
    body = '// client.request(secret)\nlet note = "client.request(secret)";\n'
    assert _names(_rust_call_sites, body) == set()


def test_rust_block_comment_mention_masked() -> None:
    assert _names(_rust_call_sites, "/* client.request(x) */") == set()


# --------------------------------------------------------------------------- #
# Java                                                                        #
# --------------------------------------------------------------------------- #
def test_java_real_call_captured() -> None:
    assert "client.execute" in _names(_java_call_sites, "client.execute(req);")


def test_java_comment_and_string_mentions_masked() -> None:
    body = '// client.execute(secret)\nString s = "client.execute(secret)";\n'
    assert _names(_java_call_sites, body) == set()


# --------------------------------------------------------------------------- #
# Ruby (# comments)                                                           #
# --------------------------------------------------------------------------- #
def test_ruby_real_call_captured() -> None:
    assert "client.get" in _names(_ruby_call_sites, "client.get(url)")


def test_ruby_comment_and_string_mentions_masked() -> None:
    body = '# client.get(secret)\ns = "client.get(secret)"\n'
    assert _names(_ruby_call_sites, body) == set()


# --------------------------------------------------------------------------- #
# C#                                                                          #
# --------------------------------------------------------------------------- #
def test_csharp_real_call_captured() -> None:
    assert "client.Send" in _names(_csharp_call_sites, "client.Send(req);")


def test_csharp_comment_and_string_mentions_masked() -> None:
    body = '// client.Send(secret)\nvar s = "client.Send(secret)";\n'
    assert _names(_csharp_call_sites, body) == set()
